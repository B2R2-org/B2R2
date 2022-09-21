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
open System.Collections.Generic
open B2R2
open B2R2.FrontEnd.BinFile

/// File type.
type ELFFileType =
  | ETNone = 0x0us
  | Relocatable = 0x1us
  | Executable = 0x2us
  | SharedObject = 0x3us
  | Core = 0x4us

/// ABI type.
type OSABI =
  | ABISystemV = 0x0uy
  | ABIHPUX = 0x1uy
  | ABINetBSD = 0x2uy
  | ABILinux = 0x3uy
  | ABISolaris = 0x6uy
  | ABIAIX = 0x7uy
  | ABIIRIX = 0x8uy
  | ABIFreeBSD = 0x9uy

/// ELF header.
type ELFHeader = {
  Class: WordSize
  Endian: Endian
  Version: uint32
  OSABI: OSABI
  OSABIVersion: uint32
  ELFFileType: ELFFileType
  MachineType: Architecture
  EntryPoint: uint64
  PHdrTblOffset: uint64
  SHdrTblOffset: uint64
  ELFFlags: uint32
  HeaderSize: uint16
  PHdrEntrySize: uint16
  PHdrNum: uint16
  SHdrEntrySize: uint16
  SHdrNum: uint16
  SHdrStrIdx: uint16
}

/// This member categorizes the section's contents and semantics.
type SectionType =
  /// This section is inactive.
  | SHTNull = 0x00u
  /// This section holds information defined by the program, whose format and
  /// meaning are determined solely by the program.
  | SHTProgBits = 0x01u
  /// This section holds a symbol table.
  | SHTSymTab = 0x02u
  /// This section holds a string table.
  | SHTStrTab = 0x03u
  /// This section holds relocation entries with explicit addends.
  | SHTRela = 0x04u
  /// This section holds a symbol hash table. All ELF files participating in
  /// dynamic linking must contain a symbol hash table.
  | SHTHash = 0x05u
  /// This section holds information for dynamic linking.
  | SHTDynamic = 0x06u
  /// This section holds a note.
  | SHTNote = 0x07u
  /// This section occupies no space, although SecOffset contains a conceptual
  /// offset to it.
  | SHTNoBits = 0x08u
  /// This section holds relocation entries without explicit addends.
  | SHTRel = 0x09u
  /// This section is reserved (unknown purpose).
  | SHTShLib = 0x0au
  /// This section contains a minimal set of dynamic linking symbols.
  | SHTDynSym = 0x0bu
  /// This section contains initialization function pointers.
  | SHTInitArray = 0x0eu
  /// This section contains termination function pointers.
  | SHTFiniArray = 0x0fu
  /// This section contains pre-initialization function pointers.
  | SHTPreInitArray = 0x10u
  /// This section holds section group information.
  | SHTGroup = 0x11u
  /// This section holds section indexes.
  | SHTSymTabShIdx = 0x12u
  /// This section marks the start of processor-specific section type.
  | SHTLoProc = 0x70000000u
  | SHTARMExIdx = 0x70000001u
  | SHTARMPreMap = 0x70000002u
  | SHTARMAttr = 0x70000003u
  | SHTARMDebug = 0x70000004u
  | SHTARMOverlay = 0x70000005u
  | SHTMIPSRegInfo = 0x70000006u
  | SHTMIPSOptions = 0x7000000du
  | SHTMIPSABIFlags = 0x7000002au
  /// This section marks the end of processor-specific section type.
  | SHTHiProc = 0x7fffffffu
  /// This section specifies the lower bound of program-specific section type.
  | SHTLoUser = 0x80000000u
  /// This section specifies the upper bound of program-specific section type.
  | SHTHiUser = 0xffffffffu
  | SHTGNUAttributes = 0x6ffffff5u
  | SHTGNUHash = 0x6ffffff6u
  | SHTGNULibList = 0x6ffffff7u
  /// This section holds Linux-specific version information (Elfxx_VerDef). This
  /// stores version information of functions defined in the binary.
  | SHTGNUVerDef = 0x6ffffffdu
  /// This section holds Linux-specific version information (Elfxx_VerNeed).
  /// This stores version information of external functions, which is needed by
  /// the caller binary.
  | SHTGNUVerNeed = 0x6ffffffeu
  /// This section holds Linux-specific version information. It specifically
  /// contains an array of elements of type Elfxx_Half. It has as many entries
  /// as the dynamic symbol table.
  | SHTGNUVerSym = 0x6fffffffu

/// Sections support 1-bit flags that describe miscellaneous attributes.
[<FlagsAttribute>]
type SectionFlag =
  /// This section contains data that should be writable during process
  /// execution.
  | SHFWrite            = 0x1UL
  /// This section occupies memory during process execution.
  | SHFAlloc            = 0x2UL
  /// This section contains executable machine code.
  | SHFExecInstr        = 0x4UL
  /// This section may be merged.
  | SHFMerge            = 0x10UL
  /// This section contains string.
  | SHFString           = 0x20UL
  /// This section holds section indexes.
  | SHFInfoLink         = 0x40UL
  /// This section adds special ordering requirements to the link editor.
  | SHFLinkOrder        = 0x80UL
  /// This section requires special OS-specific processing beyond the standard
  /// linking rules to avoid incorrect behavior
  | SHFOSNonConforming  = 0x100UL
  /// This section is a member, perhaps the only one, of a section group.
  | SHFGroup            = 0x200UL
  /// This section contains TLS data.
  | SHFTLS              = 0x400UL
  /// This section contains compressed data.
  | SHFCompressed       = 0x800UL
  /// All bits included in this mask are reserved for operating system-specific
  /// semantics.
  | SHFMaskOS           = 0x0ff00000UL
  /// All bits included in this mask are reserved for processor-specific
  /// semantics.
  | SHFMaskProc         = 0xf0000000UL
  /// This section requires ordering in relation to other sections of the same
  /// type.
  | SHFOrdered          = 0x40000000UL
  /// This section is excluded from input to the link-edit of an executable or
  /// shared object
  | SHFExclude          = 0x80000000UL
  /// This section can hold more than 2GB.
  | SHFX8664Large       = 0x10000000UL

/// ELF Section
type ELFSection = {
  /// Unique section number.
  SecNum: int
  /// The name of the section.
  SecName: string
  /// Categorizes the section's contents and semantics.
  SecType: SectionType
  /// Misc. attributes about the section.
  SecFlags: SectionFlag
  /// The address at which the section's first byte should reside. If this
  /// section will not appear in the process memory, this value is 0.
  SecAddr: Addr
  /// Byte offset from the beginning of the file to the first byte in the
  /// section.
  SecOffset: uint64
  /// The section's size in bytes.
  SecSize: uint64
  /// A section header table index link. The interpretation of this field
  /// depends on the section type.
  SecLink: uint32
  /// Extra information. The interpretation of this info depends on the section
  /// type.
  SecInfo: uint32
  /// Some sections have address alignment constraints.
  SecAlignment: uint64
  /// Some sections hold a table of fixed-size entries, such as a symbol
  /// table. For such a section, this member gives the size in bytes of each
  /// entry.
  SecEntrySize: uint64
}

/// Section information.
type SectionInfo = {
  /// Section by address.
  SecByAddr: ARMap<ELFSection>
  /// Section by name.
  SecByName: Map<string, ELFSection>
  /// Section by its number.
  SecByNum: ELFSection []
  /// Static symbol section numbers.
  StaticSymSecNums: int list
  /// Dynamic symbol section numbers.
  DynSymSecNums: int list
  /// GNU version symbol section.
  VerSymSec: ELFSection option
  /// GNU version need section.
  VerNeedSec: ELFSection option
  /// GNU version definition section.
  VerDefSec: ELFSection option
}

/// ELF dynamic tags.
type DynamicTag =
  | DT_NULL = 0UL
  | DT_NEEDED = 1UL
  | DT_PLTRELSZ = 2UL
  | DT_PLTGOT = 3UL
  | DT_HASH = 4UL
  | DT_STRTAB = 5UL
  | DT_SYMTAB = 6UL
  | DT_RELA = 7UL
  | DT_RELASZ = 8UL
  | DT_RELAENT = 9UL
  | DT_STRSZ = 10UL
  | DT_SYMENT = 11UL
  | DT_INIT = 12UL
  | DT_FINI = 13UL
  | DT_SONAME = 14UL
  | DT_RPATH = 15UL
  | DT_SYMBOLIC = 16UL
  | DT_REL = 17UL
  | DT_RELSZ = 18UL
  | DT_RELENT = 19UL
  | DT_PLTREL = 20UL
  | DT_DEBUG = 21UL
  | DT_TEXTREL = 22UL
  | DT_JMPREL = 23UL
  | DT_BIND_NOW = 24UL
  | DT_INIT_ARRAY = 25UL
  | DT_FINI_ARRAY = 26UL
  | DT_INIT_ARRAYSZ = 27UL
  | DT_FINI_ARRAYSZ = 28UL
  | DT_RUNPATH = 29UL
  | DT_FLAGS = 30UL
  | DT_PREINIT_ARRAY = 32UL
  | DT_PRE_INIT_ARRAYSZ = 33UL
  | DT_MAXPOSTAGS = 34UL
  | DT_FLAGS_1 = 0x6ffffffbUL
  | DT_RELACOUNT = 0x6ffffff9UL
  | DT_LOOS = 0x6000000dUL
  | DT_HIOS = 0x6ffff000UL
  | DT_VERSYM = 0x6ffffff0UL
  | DT_VERNEED = 0x6ffffffeUL
  | DT_VERNEEDNUM = 0x6fffffffUL
  | DT_VALRNGLO = 0x6ffffd00UL
  | DT_GNU_PRELINKED = 0x6ffffdf5UL
  | DT_GNU_CONFLICTSZ = 0x6ffffdf6UL
  | DT_GNU_LIBLISTSZ = 0x6ffffdf7UL
  | DT_CHECKSUM = 0x6ffffdf8UL
  | DT_PLTPADSZ = 0x6ffffdf9UL
  | DT_MOVEENT = 0x6ffffdfaUL
  | DT_MOVESZ = 0x6ffffdfbUL
  | DT_FEATURE = 0x6ffffdfcUL
  | DT_POSFLAG_1 = 0x6ffffdfdUL
  | DT_SYMINSZ = 0x6ffffdfeUL
  | DT_SYMINENT = 0x6ffffdffUL
  | DT_VALRNGHI = 0x6ffffdffUL
  | DT_ADDRRNGLO = 0x6ffffe00UL
  | DT_GNU_HASH = 0x6ffffef5UL
  | DT_TLSDESC_PLT = 0x6ffffef6UL
  | DT_TLSDESC_GOT = 0x6ffffef7UL
  | DT_GNU_CONFLICT = 0x6ffffef8UL
  | DT_GNU_LIBLIST = 0x6ffffef9UL
  | DT_CONFIG = 0x6ffffefaUL
  | DT_DEPAUDIT = 0x6ffffefbUL
  | DT_AUDIT = 0x6ffffefcUL
  | DT_PLTPAD = 0x6ffffefdUL
  | DT_MOVETAB = 0x6ffffefeUL
  | DT_SYMINFO = 0x6ffffeffUL
  | DT_ADDRRNGHI = 0x6ffffeffUL
  | DT_PPC_GOT = 0x70000000UL
  | DT_PPC_OPT = 0x70000001UL
  | DT_PPC64_GLINK = 0x70000000UL
  | DT_PPC64_OPD = 0x70000001UL
  | DT_PPC64_OPDSZ = 0x70000002UL
  | DT_SPARC_REGISTER = 0x70000001UL
  | DT_MIPS_RLD_VERSION = 0x70000001UL
  | DT_MIPS_TIME_STAMP = 0x70000002UL
  | DT_MIPS_ICHECKSUM = 0x70000003UL
  | DT_MIPS_IVERSION = 0x70000004UL
  | DT_MIPS_FLAGS = 0x70000005UL
  | DT_MIPS_BASE_ADDRESS = 0x70000006UL
  | DT_MIPS_MSYM = 0x70000007UL
  | DT_MIPS_CONFLICT = 0x70000008UL
  | DT_MIPS_LIBLIST = 0x70000009UL
  | DT_MIPS_LOCAL_GOTNO = 0x7000000aUL
  | DT_MIPS_CONFLICTNO = 0x7000000bUL
  | DT_MIPS_LIBLISTNO = 0x70000010UL
  | DT_MIPS_SYMTABNO = 0x70000011UL
  | DT_MIPS_UNREFEXTNO = 0x70000012UL
  | DT_MIPS_GOTSYM = 0x70000013UL
  | DT_MIPS_HIPAGENO = 0x70000014UL
  | DT_MIPS_RLD_MAP = 0x70000016UL
  | DT_MIPS_DELTA_CLASS = 0x70000017UL
  | DT_MIPS_DELTA_CLASS_NO = 0x70000018UL
  | DT_MIPS_DELTA_INSTANCE = 0x70000019UL
  | DT_MIPS_DELTA_INSTANCE_NO = 0x7000001aUL
  | DT_MIPS_DELTA_RELOC = 0x7000001bUL
  | DT_MIPS_DELTA_RELOC_NO = 0x7000001cUL
  | DT_MIPS_DELTA_SYM = 0x7000001dUL
  | DT_MIPS_DELTA_SYM_NO = 0x7000001eUL
  | DT_MIPS_DELTA_CLASSSYM = 0x70000020UL
  | DT_MIPS_DELTA_CLASSSYM_NO = 0x70000021UL
  | DT_MIPS_CXX_FLAGS = 0x70000022UL
  | DT_MIPS_PIXIE_INIT = 0x70000023UL
  | DT_MIPS_SYMBOL_LIB = 0x70000024UL
  | DT_MIPS_LOCALPAGE_GOTIDX = 0x70000025UL
  | DT_MIPS_LOCAL_GOTIDX = 0x70000026UL
  | DT_MIPS_HIDDEN_GOTIDX = 0x70000027UL
  | DT_MIPS_PROTECTED_GOTIDX = 0x70000028UL
  | DT_MIPS_OPTIONS = 0x70000029UL
  | DT_MIPS_INTERFACE = 0x7000002aUL
  | DT_MIPS_DYNSTR_ALIGN = 0x7000002bUL
  | DT_MIPS_INTERFACE_SIZE = 0x7000002cUL
  | DT_MIPS_RLD_TEXT_RESOLVE_ADDR = 0x7000002dUL
  | DT_MIPS_PERF_SUFFIX = 0x7000002eUL
  | DT_MIPS_COMPACT_SIZE = 0x7000002fUL
  | DT_MIPS_GP_VALUE = 0x70000030UL
  | DT_MIPS_AUX_DYNAMIC = 0x70000031UL
  | DT_MIPS_PLTGOT = 0x70000032UL
  | DT_MIPS_RWPLT = 0x70000034UL
  | DT_MIPS_RLD_MAP_REL = 0x70000035UL

/// Dynamic section entry.
type DynamicSectionEntry = {
  DTag: DynamicTag
  DVal: uint64
}

/// A symbol's binding determines the linkage visibility and behavior.
type SymbolBind =
  /// Local symbols are not visible outside. Local symbols of the same name may
  /// exist in multiple files without interfering with each other.
  | STBLocal = 0x0uy
  /// Global symbols are visible to all object files being combined.
  | STBGlobal = 0x1uy
  /// Weak symbols resemble global symbols, but their definitions have lower
  /// precedence.
  | STBWeak = 0x2uy
  /// The lower bound of OS-specific binding type.
  | STBLoOS = 0xauy
  /// The upper bound of OS-specific binding type.
  | STBHiOS = 0xcuy
  /// The lower bound of processor-specific binding type.
  | STBLoProc = 0xduy
  /// The upper bound of processor-specific binding type.
  | STBHiProc = 0xfuy

/// A symbol's type provides a general classification for the associated entity.
type SymbolType =
  /// Symbol's type is not specified.
  | STTNoType = 0x00uy
  /// This symbol is associated with a data object, such as variable and an
  /// array.
  | STTObject = 0x01uy
  /// This symbol is associated with a function.
  | STTFunc = 0x02uy
  /// This symbol is associated with a section. Symbol table entries of this
  /// type exist primarily for relocation and normally have STBLocal binding.
  | STTSection = 0x03uy
  /// This symbol represents the name of the source file associated with the
  /// object file.
  | STTFile = 0x04uy
  /// This symbol labels an uninitialized common block.
  | STTCommon = 0x05uy
  /// The symbol specifies a Thread-Local Storage entity.
  | STTTLS = 0x06uy
  /// A symbol with type STT_GNU_IFUNC is a function, but the symbol does not
  /// provide the address of the function as usual. Instead, the symbol provides
  /// the address of a function which returns a pointer to the actual function.
  | STTGNUIFunc = 0x0auy
  /// The lower bound of OS-specific symbol type.
  | STTLoOS = 0x0auy
  /// The upper bound of OS-specific binding type.
  | STTHiOS = 0x0cuy
  /// The lower bound of processor-specific symbol type.
  | STTLoProc = 0x0duy
  /// The upper bound of processor-specific symbol type.
  | STTHiProc = 0x0fuy

/// This member currently specifies a symbol's visibility
type SymbolVisibility =
  /// Use the visibility specified by the symbol's binding type (SymbolBind).
  | STVDefault = 0x0uy
  /// This visibility attribute is currently reserved.
  | STVInternal = 0x01uy
  /// A symbol defined in the current component is hidden if its name is not
  /// visible to other components. Such a symbol is necessarily protected. This
  /// attribute is used to control the external interface of a component. An
  /// object named by such a symbol may still be referenced from another
  /// component if its address is passed outside.
  | STVHidden = 0x02uy
  /// A symbol defined in the current component is protected if it is visible in
  /// other components but cannot be preempted. Any reference to such a symbol
  /// from within the defining component must be resolved to the definition in
  /// that component, even if there is a definition in another component that
  /// would interpose by the default rules.
  | STVProtected = 0x03uy

/// Every symbol table entry is defined in relation to some section.
/// This member holds the relevant section header table index.
type SectionHeaderIdx =
  /// This is the start of the reserved range.
  | SHNLoReserve
  /// The symbol is undefined. Linker should update references to this symbol
  /// with the actual definition from another file.
  | SHNUndef
  /// The lower bound of processor-specific section index value.
  | SHNLoProc
  /// The upper bound of processor-specific section index value.
  | SHNHiProc
  /// The lower bound of OS-specific section index value.
  | SHNLoOS
  /// The upper bound of OS-specific section index value.
  | SHNHiOS
  /// The symbol has an absolute value that will not change because of
  /// relocation.
  | SHNABS
  /// The symbol labels a common block that has not yet been allocated.
  | SHNCommon
  /// An escape value indicating that the actual section header index is too
  /// large to fit in the containing field. The header section index is found in
  /// another location specific to the structure where it appears.
  | SHNXIndex
  /// The upper boundary of the range of the reserved range.
  | SHNHiReserve
  /// This symbol index holds an index into the section header table.
  | SecIdx of int
with
  static member IndexFromInt n =
    match n with
    | 0x00 -> SHNUndef
    | 0xff00 -> SHNLoReserve
    | 0xfff1 -> SHNABS
    | 0xfff2 -> SHNCommon
    | n -> SecIdx n

type VersionType =
  /// Regular version number.
  | VerRegular
  /// Unversioned local symbol.
  | VerLocal
  /// Unversioned global symbol.
  | VerGlobal
  /// Hidden symbol.
  | VerHidden

/// Symbol version information.
type SymVerInfo = {
  /// Version type.
  VerType: VersionType
  /// Version string.
  VerName: string
}

type ELFSymbol = {
  /// Address of the symbol.
  Addr: Addr
  /// Symbol's name.
  SymName: string
  /// Size of the symbol (e.g., size of the data object).
  Size: uint64
  /// Symbol binding.
  Bind: SymbolBind
  /// Symbol type.
  SymType: SymbolType
  /// Symbol visibility.
  Vis: SymbolVisibility
  /// The index of the relevant section with regard to this symbol.
  SecHeaderIndex: SectionHeaderIdx
  /// Parent section of this section.
  ParentSection: ELFSection option
  /// Version information.
  VerInfo: SymVerInfo option
  /// ArchOperationMode.
  ArchOperationMode: ArchOperationMode
}

/// Relocation type for x86.
type RelocationX86 =
  /// No relocation.
  | R_386_NONE = 0UL
  /// Direct 32-bit (S + A).
  | R_386_32 = 1UL
  /// PC-relative 32-bit (S + A - P).
  | R_386_PC32 = 2UL
  /// 32-bit GOT entry (G + A).
  | R_386_GOT32 = 3UL
  /// 32-bit PLT entry (L + A - P).
  | R_386_PLT32 = 4UL
  /// Copy symbol at runtime.
  | R_386_COPY = 5UL
  /// Create GOT entry (S).
  | R_386_GLOB_DATA = 6UL
  /// Create PLT entry (S).
  | R_386_JUMP_SLOT = 7UL
  /// Adjust by program base (S + A).
  | R_386_RELATIVE = 8UL
  /// 32-bit offset to GOT (S + A - GOT).
  | R_386_GOTOFF = 9UL
  /// PC-relative offset to GOT (GOT + A - P).
  | R_386_GOTPC = 10UL
  /// (L + A).
  | R_386_32PLT = 11UL
  | R_386_TLS_TPOFF = 14UL
  | R_386_TLS_IE = 15UL
  | R_386_TLS_GOTIE = 16UL
  | R_386_TLS_LE = 17UL
  | R_386_TLS_GD = 18UL
  | R_386_TLS_LDM = 19UL
  /// (S + A).
  | R_386_16 = 20UL
  /// (S + A - P).
  | R_386_PC16 = 21UL
  /// (S + A).
  | R_386_8 = 22UL
  /// (S + A - P).
  | R_386_PC8 = 23UL
  | R_386_TLS_GD_32 = 24UL
  | R_386_TLS_GD_PUSH = 25UL
  | R_386_TLS_GD_CALL = 26UL
  | R_386_TLS_GD_POP = 27UL
  | R_386_TLS_LDM_32 = 28UL
  | R_386_TLS_LDM_PUSH = 29UL
  | R_386_TLS_LDM_CALL = 30UL
  | R_386_TLS_LDM_POP = 31UL
  | R_386_TLS_LDO_32 = 32UL
  | R_386_TLS_IE_32 = 33UL
  | R_386_TLS_LE_32 = 34UL
  | R_386_TLS_DTPMOD32 = 35UL
  | R_386_TLS_DTPOFF32 = 36UL
  | R_386_TLS_TPOFF32 = 37UL
  /// (Z + A).
  | R_386_SIZE32 = 38UL
  /// x86 more TLS relocations
  | R_386_TLS_GOTDESC = 39UL
  | R_386_TLS_DESC_CALL = 40UL
  | R_386_TLS_DESC = 41UL
  /// Indirect (B + A).
  | R_386_IRELATIVE = 42UL
  /// (G + A - GOT/G + A)
  | R_386_GOT32X = 43UL
  /// (A + (S >> 4)).
  | R_386_SEG16 = 44UL
  /// (A - S).
  | R_386_SUB16 = 45UL
  /// (A - S).
  | R_386_SUB32 = 46UL

/// Relocation type for x86-64.
type RelocationX64 =
  /// No relocation.
  | R_X86_64_None = 0UL
  /// Direct 64-bit.
  | R_X86_64_64 = 1UL
  /// PC-relative 32-bit.
  | R_X86_64_PC32 = 2UL
  /// 32-bit GOT entry.
  | R_X86_64_GOT32 = 3UL
  /// 32-bit PLT entry.
  | R_X86_64_PLT32 = 4UL
  /// Copy symbol at runtime.
  | R_X86_64_COPY = 5UL
  /// Create GOT entry.
  | R_X86_64_GLOB_DATA = 6UL
  /// Create PLT entry.
  | R_X86_64_JUMP_SLOT = 7UL
  /// Adjust by program base.
  | R_X86_64_RELATIVE = 8UL
  /// 32-bit signed PC-relative offset to GOT.
  | R_X86_64_GOTPCREL = 9UL
  /// Direct 32-bit zero extended.
  | R_X86_64_32 = 10UL
  /// Direct 32-bit sign extended.
  | R_X86_64_32S = 11UL
  /// Direct 16-bit zero extended.
  | R_X86_64_16 = 12UL
  /// 16-bit sign extended PC relative.
  | R_X86_64_PC16 = 13UL
  /// Direct 8-bit sign extended.
  | R_X86_64_8 = 14UL
  /// 8-bit sign extended PC relative.
  | R_X86_64_PC8 = 15UL
  /// PC-relative 64 bit.
  | R_X86_64_PC64 = 24UL
  /// 64-bit offset to GOT.
  | R_X86_64_GOTOFF64 = 25UL
  /// 32-bit signed PC-relative offset to GOT.
  | R_X86_64_GOTPC32 = 26UL
  /// 64-bit GOT entry offset.
  | R_X86_64_GOT64 = 27UL
  /// 64-bit PC-relative offset to GOT entry.
  | R_X86_64_GOTPCREL64 = 28UL
  /// 64-bit PC relative offset to GOT.
  | R_X86_64_GOTPC64 = 29UL
  /// 64-bit GOT entry offset requiring PLT.
  | R_X86_64_GOTPLT64 = 30UL
  /// 64-bit GOT relative offset to PLT entry.
  | R_X86_64_PLTOFF64 = 31UL
  /// Size of symbol plus 32-bit addend.
  | R_X86_64_SIZE32 = 32UL
  /// Size of symbol plus 64-bit addend.
  | R_X86_64_SIZE64 = 33UL
  /// Adjust indirectly by program base.
  | R_X86_64_IRELATIVE = 37UL

/// Relocation type for ARMv7.
type RelocationARMv7 =
  /// No reloc.
  | R_ARM_None = 0UL
  /// PC-relative 26-bit branch.
  | R_ARM_PC24 = 1UL
  /// Direct 32 bit.
  | R_ARM_ABS32 = 2UL
  /// PC-relative 32 bit.
  | R_ARM_REL32 = 3UL
  /// PC-relative LDR.
  | R_ARM_LDR_PC_G0 = 4UL
  /// Direct 16 bit.
  | R_ARM_ABS16 = 5UL
  /// Direct 12 bit.
  | R_ARM_ABS12 = 6UL
  /// Direct 8 bit.
  | R_ARM_ABS8 = 8UL
  /// Copy symbol at runtime.
  | R_ARM_COPY = 20UL
  /// Create GOT entry.
  | R_ARM_GLOB_DATA = 21UL
  /// Create PLT entry.
  | R_ARM_JUMP_SLOT = 22UL
  /// Adjust by program base.
  | R_ARM_RELATIVE = 23UL
  /// 32-bit offset to GOT.
  | R_ARM_GOTOFF32 = 24UL
  /// 32-bit PC-relative offset to GOT.
  | R_ARM_BASE_PREL = 25UL
  /// 32-bit GOT entry.
  | R_ARM_GOT_BREL = 26UL
  /// 32-bit PLT address.
  | R_ARM_PLT32 = 27UL

/// Relocation type for ARMv8.
type RelocationARMv8 =
  /// No reloc.
  | R_AARCH64_NONE = 0UL
  /// Direct 64 bit.
  | R_AARCH64_ABS64 = 257UL
  /// Direct 32 bit.
  | R_AARCH64_ABS32 = 258UL
  /// Direct 16 bit.
  | R_AARCH64_ABS16 = 259UL
  /// PC-relative 64 bit.
  | R_AARCH64_PREL64 = 260UL
  /// PC-relative 32 bit.
  | R_AARCH64_PREL32 = 261UL
  /// PC-relative 16 bit.
  | R_AARCH64_PREL16 = 262UL
  /// GOT-relative 64 bit.
  | R_AARCH64_GOTREL64 = 307UL
  /// GOT-relative 32 bit.
  | R_AARCH64_GOTREL32 = 308UL
  /// Copy symbol at runtime.
  | R_AARCH64_COPY = 1024UL
  /// Create GOT entry.
  | R_AARCH64_GLOB_DATA = 1025UL
  /// Create PLT entry.
  | R_AARCH64_JUMP_SLOT = 1026UL
  /// Delta(S) + A.
  | R_AARCH64_RELATIVE = 1027UL

/// Relocation type for MIPS.
type RelocationMIPS =
  /// No reloc.
  | R_MIPS_NONE = 0UL
  /// Direct 16 bit.
  | R_MIPS_16 = 1UL
  /// Direct 32 bit.
  | R_MIPS_32 = 2UL
  /// PC-relative 32 bit.
  | R_MIPS_REL32 = 3UL
  /// Direct 26 bit shifted.
  | R_MIPS_26 = 4UL
  /// High 16 bit.
  | R_MIPS_HI16 = 5UL
  /// Low 16 bit.
  | R_MIPS_LO16 = 6UL
  /// GP-relative 16 bit.
  | R_MIPS_GPREL16 = 7UL
  /// 16-bit literal entry.
  | R_MIPS_LITERAL = 8UL
  /// 16-bit GOT entry.
  | R_MIPS_GOT16 = 9UL
  /// PC-relative 16 bit.
  | R_MIPS_PC16 = 10UL
  /// 16-bit GOT entry for function.
  | R_MIPS_CALL16 = 11UL
  /// GP-relative 32 bit.
  | R_MIPS_GPREL32 = 12UL
  /// 5-bit shift field.
  | R_MIPS_SHIFT5 = 16UL
  /// 6-bit shift field.
  | R_MIPS_SHIFT6 = 17UL
  /// direct 64 bit.
  | R_MIPS_64 = 18UL
  /// displacement in the GOT.
  | R_MIPS_GOT_DISP = 19UL
  /// displacement to page pointer in the GOT.
  | R_MIPS_GOT_PAGE = 20UL
  /// Offset from page pointer in the GOT.
  | R_MIPS_GOT_OFST = 21UL
  /// HIgh 16 bits of displacement in the GOT.
  | R_MIPS_GOT_HI16 = 22UL
  /// Low 16 bits of displacement in the GOT.
  | R_MIPS_GOT_LO16 = 23UL
  /// 64-bit subtraction.
  | R_MIPS_SUB = 24UL
  /// Insert the addend as an instruction.
  | R_MIPS_INSERT_A = 25UL
  /// Insert the addend as an instruction, and change all relocations to
  /// refer to the old instruction at the address.
  | R_MIPS_INSERT_B = 26UL
  /// Delete a 32 bit instruction.
  | R_MIPS_DELETE = 27UL
  /// Get the higher value of a 64 bit addend.
  | R_MIPS_HIGHER = 28UL
  /// Get the highest value of a 64 bit addend.
  | R_MIPS_HIGHEST = 29UL
  /// High 16 bits of displacement in GOT.
  | R_MIPS_CALL_HI16 = 30UL
  /// Low 16 bits of displacement in GOT.
  | R_MIPS_CALL_LO16 = 31UL
  /// Section displacement, used by an associated event location section.
  | R_MIPS_SCN_DISP = 32UL
  /// PC-relative 16 bit.
  | R_MIPS_REL16 = 33UL
  /// Similiar to R_MIPS__REL32, but used for relocations in a GOT section.
  | R_MIPS_RELGOT = 36UL
  /// Protected jump conversion.
  | R_MIPS_JALR = 37UL
  /// Module number 32 bit.
  | R_MIPS_TLS_DTPMOD32 = 38UL
  /// Module-relative offset 32 bit.
  | R_MIPS_TLS_DTPREL32 = 39UL
  /// Module number 64 bit.
  | R_MIPS_TLS_DTPMOD64 = 40UL
  /// Module-relative offset 64 bit.
  | R_MIPS_TLS_DTPREL64 = 41UL
  /// 16 bit GOT offset for GD.
  | R_MIPS_TLS_GD = 42UL
  /// 16 bit GOT offset for LDM.
  | R_MIPS_TLS_LDM = 43UL
  /// Module-relative offset, high 16 bits.
  | R_MIPS_TLS_DTPREL_HI16 = 44UL
  /// Module-relative offset, low 16 bits.
  | R_MIPS_TLS_DTPREL_LO16 = 45UL
  /// 16 bit GOT offset for IE.
  | R_MIPS_TLS_GOTPREL = 46UL
  /// TP-relative offset, 32 bit.
  | R_MIPS_TLS_TPREL32 = 47UL
  /// TP-relative offset, 64 bit.
  | R_MIPS_TLS_TPREL64 = 48UL
  /// TP-relative offset, high 16 bits.
  | R_MIPS_TLS_TPREL_HI16 = 49UL
  /// TP-relative offset, low 16 bits.
  | R_MIPS_TLS_TPREL_LO16 = 50UL
  /// 32 bit relocation with no addend.
  | R_MIPS_GLOB_DAT = 51UL
  /// Copy symbol at runtime.
  | R_MIPS_COPY = 126UL
  /// Jump slot.
  | R_MIPS_JUMP_SLOT = 127UL
  /// 32-bit PC-relative.
  | R_MIPS_PC32 = 248UL

/// Relocation type for SH4.
type RelocationSH4 =
  | R_SH_NONE = 0UL
  | R_SH_DIR32 = 1UL
  | R_SH_REL32 = 2UL
  | R_SH_DIR8WPN = 3UL
  | R_SH_IND12W = 4UL
  | R_SH_DIR8WPL = 5UL
  | R_SH_DIR8WPZ = 6UL
  | R_SH_DIR8BP = 7UL
  | R_SH_DIR8W = 8UL
  | R_SH_DIR8L = 9UL
  | R_SH_LOOP_START = 10UL
  | R_SH_LOOP_END = 11UL
  | R_SH_GNU_VTINHERIT = 22UL
  | R_SH_GNU_VTENTRY = 23UL
  | R_SH_SWITCH8 = 24UL
  | R_SH_SWITCH16 = 25UL
  | R_SH_SWITCH32 = 26UL
  | R_SH_USES = 27UL
  | R_SH_COUNT = 28UL
  | R_SH_ALIGN = 29UL
  | R_SH_CODE = 30UL
  | R_SH_DATA = 31UL
  | R_SH_LABEL = 32UL
  | R_SH_DIR16 = 33UL
  | R_SH_DIR8 = 34UL
  | R_SH_DIR8UL = 35UL
  | R_SH_DIR8UW = 36UL
  | R_SH_DIR8U = 37UL
  | R_SH_DIR8SW = 38UL
  | R_SH_DIR8S = 39UL
  | R_SH_DIR4UL = 40UL
  | R_SH_DIR4UW = 41UL
  | R_SH_DIR4U = 42UL
  | R_SH_PSHA = 43UL
  | R_SH_PSHL = 44UL
  | R_SH_DIR5U = 45UL
  | R_SH_DIR6U = 46UL
  | R_SH_DIR6S = 47UL
  | R_SH_DIR10S = 48UL
  | R_SH_DIR10SW = 49UL
  | R_SH_DIR10SL = 50UL
  | R_SH_DIR10SQ = 51UL
  | R_SH_DIR16S = 53UL
  | R_SH_TLS_GD_32 = 144UL
  | R_SH_TLS_LD_32 = 145UL
  | R_SH_TLS_LDO_32 = 146UL
  | R_SH_TLS_IE_32 = 147UL
  | R_SH_TLS_LE_32 = 148UL
  | R_SH_TLS_DTPMOD32 = 149UL
  | R_SH_TLS_DTPOFF32 = 150UL
  | R_SH_TLS_TPOFF32 = 151UL
  | R_SH_GOT32 = 160UL
  | R_SH_PLT32 = 161UL
  | R_SH_COPY = 162UL
  | R_SH_GLOB_DAT = 163UL
  | R_SH_JMP_SLOT = 164UL
  | R_SH_RELATIVE = 165UL
  | R_SH_GOTOFF = 166UL
  | R_SH_GOTPC = 167UL
  | R_SH_GOTPLT32 = 168UL
  | R_SH_GOT_LOW16 = 169UL
  | R_SH_GOT_MEDLOW16 = 170UL
  | R_SH_GOT_MEDHI16 = 171UL
  | R_SH_GOT_HI16 = 172UL
  | R_SH_GOTPLT_LOW16 = 173UL
  | R_SH_GOTPLT_MEDLOW16 = 174UL
  | R_SH_GOTPLT_MEDHI16 = 175UL
  | R_SH_GOTPLT_HI16 = 176UL
  | R_SH_PLT_LOW16 = 177UL
  | R_SH_PLT_MEDLOW16 = 178UL
  | R_SH_PLT_MEDHI16 = 179UL
  | R_SH_PLT_HI16 = 180UL
  | R_SH_GOTOFF_LOW16 = 181UL
  | R_SH_GOTOFF_MEDLOW16 = 182UL
  | R_SH_GOTOFF_MEDHI16 = 183UL
  | R_SH_GOTOFF_HI16 = 184UL
  | R_SH_GOTPC_LOW16 = 185UL
  | R_SH_GOTPC_MEDLOW16 = 186UL
  | R_SH_GOTPC_MEDHI16 = 187UL
  | R_SH_GOTPC_HI16 = 188UL
  | R_SH_GOT10BY4 = 189UL
  | R_SH_GOTPLT10BY4 = 190UL
  | R_SH_GOT10BY8 = 191UL
  | R_SH_GOTPLT10BY8 = 192UL
  | R_SH_COPY64 = 193UL
  | R_SH_GLOB_DAT64 = 194UL
  | R_SH_JMP_SLOT64 = 195UL
  | R_SH_RELATIVE64 = 196UL
  | R_SH_GOT20 = 201UL
  | R_SH_GOTOFF20 = 202UL
  | R_SH_GOTFUNCDESC = 203UL
  | R_SH_GOTFUNCDESC20 = 204UL
  | R_SH_GOTOFFFUNCDESC = 205UL
  | R_SH_GOTOFFFUNCDESC20 = 206UL
  | R_SH_FUNCDESC = 207UL
  | R_SH_FUNCDESC_VALUE = 208UL
  | R_SH_SHMEDIA_CODE = 242UL
  | R_SH_PT_16 = 243UL
  | R_SH_IMMS16 = 244UL
  | R_SH_IMMU16 = 245UL
  | R_SH_IMM_LOW16 = 246UL
  | R_SH_IMM_LOW16_PCREL = 247UL
  | R_SH_IMM_MEDLOW16 = 248UL
  | R_SH_IMM_MEDLOW16_PCREL = 249UL
  | R_SH_IMM_MEDHI16 = 250UL
  | R_SH_IMM_MEDHI16_PCREL = 251UL
  | R_SH_IMM_HI16 = 252UL
  | R_SH_IMM_HI16_PCREL = 253UL
  | R_SH_64 = 254UL
  | R_SH_64_PCREL = 255UL

/// Relocation type for RISCV.
type RelocationRISCV =
  | R_RISCV_NONE = 0UL
  | R_RISCV_32 = 1UL
  | R_RISCV_64 = 2UL
  | R_RISCV_RELATIVE = 3UL
  | R_RISCV_COPY = 4UL
  | R_RISCV_JUMP_SLOT = 5UL
  | R_RISCV_TLS_DTPMOD32 = 6UL
  | R_RISCV_TLS_DTPMOD64 = 7UL
  | R_RISCV_TLS_DTPREL32 = 8UL
  | R_RISCV_TLS_DTPREL64 = 9UL
  | R_RISCV_TLS_TPREL32 = 10UL
  | R_RISCV_TLS_TPREL64 = 11UL
  | R_RISCV_BRANCH = 16UL
  | R_RISCV_JAL = 17UL
  | R_RISCV_CALL = 18UL
  | R_RISCV_CALL_PLT = 19UL
  | R_RISCV_GOT_HI20 = 20UL
  | R_RISCV_TLS_GOT_HI20 = 21UL
  | R_RISCV_TLS_GD_HI20 = 22UL
  | R_RISCV_PCREL_HI20 = 23UL
  | R_RISCV_PCREL_LO12_I = 24UL
  | R_RISCV_PCREL_LO12_S = 25UL
  | R_RISCV_HI20 = 26UL
  | R_RISCV_LO12_I = 27UL
  | R_RISCV_LO12_S = 28UL
  | R_RISCV_TPREL_HI20 = 29UL
  | R_RISCV_TPREL_LO12_I = 30UL
  | R_RISCV_TPREL_LO12_S = 31UL
  | R_RISCV_TPREL_ADD = 32UL
  | R_RISCV_ADD8 = 33UL
  | R_RISCV_ADD16 = 34UL
  | R_RISCV_ADD32 = 35UL
  | R_RISCV_ADD64 = 36UL
  | R_RISCV_SUB8 = 37UL
  | R_RISCV_SUB16 = 38UL
  | R_RISCV_SUB32 = 39UL
  | R_RISCV_SUB64 = 40UL
  | R_RISCV_GNU_VTINHERIT = 41UL
  | R_RISCV_GNU_VTENTRY = 42UL
  | R_RISCV_ALIGN = 43UL
  | R_RISCV_RVC_BRANCH = 44UL
  | R_RISCV_RVC_JUMP = 45UL
  | R_RISCV_RVC_LUI = 46UL
  | R_RISCV_GPREL_I = 47UL
  | R_RISCV_GPREL_S = 48UL
  | R_RISCV_TPREL_I = 49UL
  | R_RISCV_TPREL_S = 50UL
  | R_RISCV_RELAX = 51UL
  | R_RISCV_SUB6 = 52UL
  | R_RISCV_SET6 = 53UL
  | R_RISCV_SET8 = 54UL
  | R_RISCV_SET16 = 55UL
  | R_RISCV_SET32 = 56UL
  | R_RISCV_32_PCREL = 57UL

/// Relocation type.
type RelocationType =
  | RelocationX86 of RelocationX86
  | RelocationX64 of RelocationX64
  | RelocationARMv7 of RelocationARMv7
  | RelocationARMv8 of RelocationARMv8
  | RelocationMIPS of RelocationMIPS
  | RelocationSH4 of RelocationSH4
  | RelocationRISCV of RelocationRISCV
with
  static member FromNum arch n =
    match arch with
    | Architecture.IntelX86 ->
      RelocationX86 <| LanguagePrimitives.EnumOfValue n
    | Architecture.IntelX64 ->
      RelocationX64 <| LanguagePrimitives.EnumOfValue n
    | Architecture.ARMv7 ->
      RelocationARMv7 <| LanguagePrimitives.EnumOfValue n
    | Architecture.AARCH32
    | Architecture.AARCH64 ->
      RelocationARMv8 <| LanguagePrimitives.EnumOfValue n
    | Architecture.MIPS32
    | Architecture.MIPS64 ->
      RelocationMIPS <| LanguagePrimitives.EnumOfValue n
    | Architecture.SH4 ->
      RelocationSH4 <| LanguagePrimitives.EnumOfValue n
    | Architecture.RISCV64 ->
      RelocationRISCV <| LanguagePrimitives.EnumOfValue n
    | _ -> invalidArg (nameof arch) "Unsupported architecture for relocation."

  static member ToString rt =
    match rt with
    | RelocationX86 t -> t.ToString ()
    | RelocationX64 t -> t.ToString ()
    | RelocationARMv7 t -> t.ToString ()
    | RelocationARMv8 t -> t.ToString ()
    | RelocationMIPS t -> t.ToString ()
    | RelocationSH4 t -> t.ToString ()
    | RelocationRISCV t -> t.ToString ()

/// Relocation entry.
type RelocationEntry = {
  /// The location at which to apply the relocation action.
  RelOffset: uint64
  /// Relocation symbol. Symbol can be None when only the addend is used.
  RelSymbol: ELFSymbol option
  /// Relocation type.
  RelType: RelocationType
  /// A constant addend used to compute the value to be stored into the
  /// relocatable field.
  RelAddend: uint64
  /// The number of the section that defines this relocation.
  RelSecNumber: int
}

/// Relocation information
type RelocInfo = {
  RelocByAddr: Dictionary<Addr, RelocationEntry>
  RelocByName: Dictionary<string, RelocationEntry>
}

/// Main data structure for storing symbol information.
type ELFSymbolInfo = {
  /// Linux-specific symbol version table containing versions required to link.
  VersionTable: Dictionary<uint16, string>
  /// A mapping from a section number to the corresponding symbol table.
  SecNumToSymbTbls: Dictionary<int, ELFSymbol[]>
  /// Address to symbol mapping.
  AddrToSymbTable: Dictionary<Addr, ELFSymbol>
}

/// This member tells what kind of segment this array element describes or
/// how to interpret the array element's information. A segment is also known as
/// a 'program header'.
type ProgramHeaderType =
  /// This program header is not used.
  | PTNull = 0x00u
  /// This is a loadable segment.
  | PTLoad = 0x01u
  /// This segment contains dynamic linking information.
  | PTDynamic = 0x02u
  /// This segment contains the location and size of a null-terminated path name
  /// to invoke an interpreter. This segment type is meaningful only for
  /// executable files, but not for shared objects. This segment may not occur
  /// more than once in a file. If it is present, it must precede any loadable
  /// segment entry.
  | PTInterp = 0x03u
  /// This segment contains the location and size of auxiliary information.
  | PTNote = 0x04u
  /// This segment type is reserved but has unspecified semantics.
  | PTShLib = 0x05u
  /// This segment specifies the location and size of the program header table
  /// itself, It may occur only if the program header table is part of the
  /// memory image of the program. If it is present, it must precede any
  /// loadable segment entry.
  | PTPhdr = 0x06u
  /// This segment contains the Thread-Local Storage template.
  | PTTLS = 0x07u
  /// The lower bound of OS-specific program header type.
  | PTLoOS = 0x60000000u
  /// The upper bound of OS-specific program header type.
  | PTHiOS = 0x6fffffffu
  /// The lower bound of processor-specific program header type.
  | PTLoProc = 0x70000000u
  /// The exception unwind table (PT_ARM_EXIDX).
  | PTARMExIdx = 0x70000001u
  /// MIPS ABI flags (PT_MIPS_ABIFLAGS).
  | PTMIPSABIFlags = 0x70000003u
  /// The upper bound of processor-specific program header type.
  | PTHiProc = 0x7fffffffu
  /// This segment specifies the location and size of the exception handling
  /// information as defined by the .eh_frame_hdr section.
  | PTGNUEHFrame = 0x6474e550u
  /// This segment specifies the permissions on the segment containing the stack
  /// and is used to indicate weather the stack should be executable. The
  /// absence of this header indicates that the stack will be executable.
  | PTGNUStack = 0x6474e551u
  /// This segment specifies the location and size of a segment which may be
  /// made read-only after relocations have been processed.
  | PTGNURelro = 0x6474e552u
  /// This segment contains PAX flags.
  | PTPAXFlags = 0x65041580u

/// An executable or shared object file's program header table is an array of
/// structures, each of which describes a segment or the other information a
/// system needs to prepare for execution. An object file segment contains one
/// or more sections. Program headers are meaningful only for executable and
/// shared object files. A file specifies its own program header size with
/// the ELF header's members.
type ProgramHeader = {
  /// Program header type.
  PHType: ProgramHeaderType
  /// Flags relevant to the segment.
  PHFlags: Permission
  /// An offset from the beginning of the file at which the first byte of the
  /// segment resides in memory.
  PHOffset: uint64
  /// The virtual address at which the first byte of the segment resides in
  /// memory.
  PHAddr: Addr
  /// The physical address of the segment. This is reserved for systems using
  /// physical addresses.
  PHPhyAddr: Addr
  /// The number of bytes in the file image of the segment.
  PHFileSize: uint64
  /// The number of bytes in the memory image of the segment. This can be
  /// greater than PHFileSize as some sections (w/ SHTNoBits type) occupy
  /// nothing in the binary file, but can be mapped in the segment at runtime.
  PHMemSize: uint64
  /// The value to which the segments are aligned in memory and in the file.
  PHAlignment: uint64
}

/// Language Specific Data Area header.
type LSDAHeader = {
  /// This is the value encoding of the landing pad pointer.
  LPValueEncoding: ExceptionHeaderValue
  /// This is the application encoding of the landing pad pointer.
  LPAppEncoding: ExceptionHeaderApplication
  /// The base of the landing pad pointers.
  LPStart: Addr option
  /// This is the value encoding of type table (TT).
  TTValueEncoding: ExceptionHeaderValue
  /// This is the application encoding of type table (TT).
  TTAppEncoding: ExceptionHeaderApplication
  /// The base of types table.
  TTBase: Addr option
  // This is the value encoding of the call site table.
  CallSiteValueEncoding: ExceptionHeaderValue
  // This is the application encoding of the call site table.
  CallSiteAppEncoding: ExceptionHeaderApplication
  // The size of call site table.
  CallSiteTableSize: uint64
}

/// An entry in the callsite table of LSDA.
type CallSiteRecord = {
  /// Offset of the callsite relative to the previous call site.
  Position: uint64
  /// Size of the callsite instruction(s).
  Length: uint64
  /// Offset of the landing pad.
  LandingPad: uint64
  /// Offset to the action table. Zero means no action entry.
  ActionOffset: int
  /// Parsed list of type filters from the action table.
  ActionTypeFilters: int64 list
}

/// LSDA. Language Specific Data Area.
type LanguageSpecificDataArea = {
  Header: LSDAHeader
  CallSiteTable: CallSiteRecord list
}

/// This tells how augmetation data is handled.
type Augmentation = {
  Format: char
  ValueEncoding: ExceptionHeaderValue
  ApplicationEncoding: ExceptionHeaderApplication
  PersonalityRoutionPointer: byte []
}

/// CIE. Common Information Entry.
type CommonInformationEntry = {
  Version: uint8
  AugmentationString: string
  CodeAlignmentFactor: uint64
  DataAlignmentFactor: int64
  ReturnAddressRegister: byte
  InitialRule: Rule
  InitialCFARegister: byte
  InitialCFA: CanonicalFrameAddress
  Augmentations: Augmentation list
}

/// FDE. Frame Description Entry.
type FrameDescriptionEntry = {
  PCBegin: Addr
  PCEnd: Addr
  LSDAPointer: Addr option
  UnwindingInfo: UnwindingEntry list
}

/// The main information block of .eh_frame. This exists roughly for every
/// object file, although one object file may have multiple CFIs.
type CallFrameInformation = {
  CIERecord: CommonInformationEntry
  FDERecord: FrameDescriptionEntry[]
}

/// Main ELF format representation.
type ELF = {
  /// ELF header.
  ELFHdr: ELFHeader
  /// Preferred base address.
  BaseAddr: Addr
  /// Segment information.
  ProgHeaders: ProgramHeader list
  /// Loadable segments.
  LoadableSegments: ProgramHeader list
  /// Loadable section numbers.
  LoadableSecNums: Set<int>
  /// Section information.
  SecInfo: SectionInfo
  /// Symbol information.
  SymInfo: ELFSymbolInfo
  /// Relocation information.
  RelocInfo: RelocInfo
  /// Procedure Linkage Table.
  PLT: ARMap<LinkageTableEntry>
  /// Global symbols (such as R_X86_64_GLOB_DAT).
  Globals: Map<Addr, ELFSymbol>
  /// Exception frames.
  ExceptionFrame: CallFrameInformation list
  /// LSDAs (Language Specific Data Areas).
  LSDAs: Map<Addr, LanguageSpecificDataArea>
  /// Invalid address ranges.
  InvalidAddrRanges: IntervalSet
  /// Not-in-file address ranges.
  NotInFileRanges: IntervalSet
  /// Executable address ranges.
  ExecutableRanges: IntervalSet
  /// ISA.
  ISA: ISA
  /// Unwinding info table.
  UnwindingTbl: Map<Addr, UnwindingEntry>
  /// IBinReader.
  BinReader: IBinReader
}
