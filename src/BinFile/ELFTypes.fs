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

namespace B2R2.BinFile.ELF

open System
open B2R2
open B2R2.BinFile

/// File type.
type ELFFileType =
  | ETNone = 0x0us
  | Relocatable = 0x1us
  | Executable = 0x2us
  | SharedObject = 0x3us
  | Core = 0x4us

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

/// ELF dynamic section tags.
type DynamicSectionTag =
  | DTNull = 0UL
  | DTNeeded = 1UL
  | DTPLTRelSz = 2UL
  | DTPLTRelGot = 3UL
  | DTHash = 4UL
  | DTStrTab = 5UL
  | DTSymTab = 6UL
  | DTRELA = 7UL
  | DTRELASz = 8UL
  | DTRELAEnt = 9UL
  | DTStrSz = 10UL
  | DTSymEnt = 11UL
  | DTInit = 12UL
  | DTFini = 13UL
  | DTSOName = 14UL
  | DTRPath = 15UL
  | DTSymbolic = 16UL
  | DTREL = 17UL
  | DTRELSz = 18UL
  | DTRELEnt = 19UL
  | DTPLTRel = 20UL
  | DTDebug = 21UL
  | DTTextRel = 22UL
  | DTJmpRel = 23UL
  | DTBindNow = 24UL
  | DTInitArray = 25UL
  | DTFiniArray = 26UL
  | DTInitArraySz = 27UL
  | DTFiniArraySz = 28UL
  | DTRunPath = 29UL
  | DTFlags = 30UL
  | DTEncoding = 31UL
  | DTPreInitArray = 32UL
  | DTPreInitArraySz = 33UL
  | DTMaxPosTags = 34UL
  | DTFlags1 = 0x6ffffffbUL
  | DTRELACount = 0x6ffffff9UL
  | DTVerSym = 0x6ffffff0UL
  | DTVerNeed = 0x6ffffffeUL
  | DTVerNeedNum = 0x6fffffffUL

/// Dynamic section entry.
type DynamicSectionEntry = {
  DTag: DynamicSectionTag
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
}

/// Relocation type for x86.
type RelocationX86 =
  /// x86: no relocation.
  | Reloc386None = 0UL
  /// x86: direct 32-bit (S + A).
  | Reloc38632 = 1UL
  /// x86: PC-relative 32-bit (S + A - P).
  | Reloc386PC32 = 2UL
  /// x86: 32-bit GOT entry (G + A).
  | Reloc386GOT32 = 3UL
  /// x86: 32-bit PLT entry (L + A - P).
  | Reloc386PLT32 = 4UL
  /// x86: copy symbol at runtime.
  | Reloc386Copy = 5UL
  /// x86: create GOT entry (S).
  | Reloc386GlobData = 6UL
  /// x86: create PLT entry (S).
  | Reloc386JmpSlot = 7UL
  /// x86: adjust by program base (S + A).
  | Reloc386Relative = 8UL
  /// x86: 32-bit offset to GOT (S + A - GOT).
  | Reloc386GOTOffset = 9UL
  /// x86: pc-relative offset to GOT (GOT + A - P).
  | Reloc386GOTPC = 10UL
  /// x86: (L + A).
  | Reloc38632PLT = 11UL
  /// x86 TLS relocations
  | Reloc386TLSTPOFF = 14UL
  | Reloc386TLSIE = 15UL
  | Reloc386TLSGOTIE = 16UL
  | Reloc386TLSLE = 17UL
  | Reloc386TLSGD = 18UL
  | Reloc386TLSLDM = 19UL
  /// x86: (S + A).
  | Reloc38616 = 20UL
  /// x86: (S + A - P).
  | Reloc386PC16 = 21UL
  /// x86: (S + A).
  | Reloc3868 = 22UL
  /// x86: (S + A - P).
  | Reloc386PC8 = 23UL
  /// x86 more TLS relocations
  | Reloc386TLSGD32 = 24UL
  | Reloc386TLSGDPUSH = 25UL
  | Reloc386TLSGDCALL = 26UL
  | Reloc386TLSGDPOP = 27UL
  | Reloc386TLSLDM32 = 28UL
  | Reloc386TLSLDMPUSH = 29UL
  | Reloc386TLSLDMCALL = 30UL
  | Reloc386TLSLDMPOP = 31UL
  | Reloc386TLSLDO32 = 32UL
  | Reloc386TLSIE32 = 33UL
  | Reloc386TLSLE32 = 34UL
  | Reloc386TLSDTPMOD32 = 35UL
  | Reloc386TLSDTPOFF32 = 36UL
  | Reloc386TLSTPOFF32 = 37UL
  /// x86: (Z + A).
  | Reloc386SIZE32 = 38UL
  /// x86 more TLS relocations
  | Reloc386TLSGOTDESC = 39UL
  | Reloc386TLSDESCCALL = 40UL
  | Reloc386TLSDESC = 41UL
  /// x86: indirect (B + A).
  | Reloc386IRELATIVE = 42UL
  /// x86: (G + A - GOT/G + A)
  | Reloc386GOT32X = 43UL
  /// x86: (A + (S >> 4)).
  | Reloc386SEG16 = 44UL
  /// x86: (A - S).
  | Reloc386SUB16 = 45UL
  /// x86: (A - S).
  | Reloc386SUB32 = 46UL

/// Relocation type for x86-64.
type RelocationX64 =
  /// x86-64: no relocation.
  | RelocX64None = 0UL
  /// x86-64: direct 64-bit.
  | RelocX6464 = 1UL
  /// x86-64: PC-relative 32-bit.
  | RelocX64PC32 = 2UL
  /// x86-64: 32-bit GOT entry.
  | RelocX64GOT32 = 3UL
  /// x86-64: 32-bit PLT entry.
  | RelocX64PLT32 = 4UL
  /// x86-64: copy symbol at runtime.
  | RelocX64Copy = 5UL
  /// x86-64: create GOT entry.
  | RelocX64GlobData = 6UL
  /// x86-64: create PLT entry.
  | RelocX64JmpSlot = 7UL
  /// x86-64: adjust by program base.
  | RelocX64Relative = 8UL
  /// x86-64: 32-bit signed PC-relative offset to GOT.
  | RelocX64GOTPCREL = 9UL
  /// x86-64: direct 32-bit zero extended.
  | RelocX6432 = 10UL
  /// x86-64: direct 32-bit sign extended.
  | RelocX6432S = 11UL
  /// x86-64: direct 16-bit zero extended.
  | RelocX6416 = 12UL
  /// x86-64: 16-bit sign extended PC relative.
  | RelocX64PC16 = 13UL
  /// x86-64: direct 8-bit sign extended.
  | RelocX648 = 14UL
  /// x86-64: 8-bit sign extended PC relative.
  | RelocX64PC8 = 15UL
  /// x86-64: PC-relative 64 bit.
  | RelocX64PC64 = 24UL
  /// x86-64: 64-bit offset to GOT.
  | RelocX64GOTOFF64 = 25UL
  /// x86-64: 32-bit signed PC-relative offset to GOT.
  | RelocX64GOTPC32 = 26UL
  /// x86-64: 64-bit GOT entry offset.
  | RelocX64GOT64 = 27UL
  /// x86-64: 64-bit PC-relative offset to GOT entry.
  | RelocX64GOTPCREL64 = 28UL
  /// x86-64: 64-bit PC relative offset to GOT.
  | RelocX64GOTPC64 = 29UL
  /// x86-64: 64-bit GOT entry offset requiring PLT.
  | RelocX64GOTPLT64 = 30UL
  /// x86-64: 64-bit GOT relative offset to PLT entry.
  | RelocX64PLTOFF64 = 31UL
  /// x86-64: size of symbol plus 32-bit addend.
  | RelocX64Size32 = 32UL
  /// x86-64: size of symbol plus 64-bit addend.
  | RelocX64Size64 = 33UL
  /// x86-64: adjust indirectly by program base.
  | RelocX64IRelative = 37UL

/// Relocation type for ARMv7.
type RelocationARMv7 =
  /// ARM: no reloc.
  | RelocARMNone = 0UL
  /// ARM: PC-relative 26-bit branch.
  | RelocARMPC24 = 1UL
  /// ARM: direct 32 bit.
  | RelocARMABS32 = 2UL
  /// ARM: PC-relative 32 bit.
  | RelocARMREL32 = 3UL
  /// ARM: PC-relative LDR.
  | RelocARMPC13 = 4UL
  /// ARM: direct 16 bit.
  | RelocARMABS16 = 5UL
  /// ARM: direct 12 bit.
  | RelocARMABS12 = 6UL
  /// ARM: direct 8 bit.
  | RelocARMABS8 = 8UL
  /// ARM: copy symbol at runtime.
  | RelocARMCopy = 20UL
  /// ARM: create GOT entry.
  | RelocARMGlobData = 21UL
  /// ARM: create PLT entry.
  | RelocARMJmpSlot = 22UL
  /// ARM: adjust by program base.
  | RelocARMRelative = 23UL
  /// ARM: 32-bit offset to GOT.
  | RelocARMGOTOffset = 24UL
  /// ARM: 32-bit PC-relative offset to GOT.
  | RelocARMGOTPC = 25UL
  /// ARM: 32-bit GOT entry.
  | RelocARMGOT32 = 26UL
  /// ARM: 32-bit PLT address.
  | RelocARMPLT32 = 27UL

/// Relocation type for ARMv8.
type RelocationARMv8 =
  /// AARCH64: no reloc.
  | RelocAARCH64None = 0UL
  /// AARCH64: direct 64 bit.
  | RelocAARCH64ABS64 = 257UL
  /// AARCH64: direct 32 bit.
  | RelocAARCH64ABS32 = 258UL
  /// AARCH64: direct 16 bit.
  | RelocAARCH64ABS16 = 259UL
  /// AARCH64: PC-relative 64 bit.
  | RelocAARCH64PREL64 = 260UL
  /// AARCH64: PC-relative 32 bit.
  | RelocAARCH64PREL32 = 261UL
  /// AARCH64: PC-relative 16 bit.
  | RelocAARCH64PREL16 = 262UL
  /// AARCH64: GOT-relative 64 bit.
  | RelocAARCH64GOTREL64 = 307UL
  /// AARCH64: GOT-relative 32 bit.
  | RelocAARCH64GOTREL32 = 308UL
  /// AARCH64: copy symbol at runtime.
  | RelocAARCH64Copy = 1024UL
  /// AARCH64: create GOT entry.
  | RelocAARCH64GlobData = 1025UL
  /// AARCH64: create PLT entry.
  | RelocAARCH64JmpSlot = 1026UL

/// Relocation type for MIPS.
type RelocationMIPS =
  /// MIPS: no reloc.
  | RelocMIPSNone = 0UL
  /// MIPS: direct 16 bit.
  | RelocMIPS16 = 1UL
  /// MIPS: direct 32 bit.
  | RelocMIPS32 = 2UL
  /// MIPS: PC-relative 32 bit.
  | RelocMIPSREL32 = 3UL
  /// MIPS: direct 26 bit shifted.
  | RelocMIPS26 = 4UL
  /// MIPS: high 16 bit.
  | RelocMIPSHigh16 = 5UL
  /// MIPS: low 16 bit.
  | RelocMIPSLow16 = 6UL
  /// MIPS: GP-relative 16 bit.
  | RelocMIPSGPREL16 = 7UL
  /// MIPS: 16-bit literal entry.
  | RelocMIPSLiteral = 8UL
  /// MIPS: 16-bit GOT entry.
  | RelocMIPSGOT16 = 9UL
  /// MIPS: PC-relative 16 bit.
  | RelocMIPSPC16 = 10UL
  /// MIPS: 16-bit GOT entry for function.
  | RelocMIPSCall16 = 11UL
  /// MIPS: GP-relative 32 bit.
  | RelocMIPSGPREL32 = 12UL

/// Relocation type.
type RelocationType =
  | RelocationX86 of RelocationX86
  | RelocationX64 of RelocationX64
  | RelocationARMv7 of RelocationARMv7
  | RelocationARMv8 of RelocationARMv8
  | RelocationMIPS of RelocationMIPS
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
    | Architecture.MIPS1
    | Architecture.MIPS2
    | Architecture.MIPS3
    | Architecture.MIPS4
    | Architecture.MIPS5
    | Architecture.MIPS32
    | Architecture.MIPS32R2
    | Architecture.MIPS32R6
    | Architecture.MIPS64
    | Architecture.MIPS64R2
    | Architecture.MIPS64R6 ->
      RelocationMIPS <| LanguagePrimitives.EnumOfValue n
    | _ -> invalidArg "Architecture" "Unsupported architecture for relocation."

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
  RelocByAddr: Map<Addr, RelocationEntry>
  RelocByName: Map<string, RelocationEntry>
}

/// Main data structure for storing symbol information.
type ELFSymbolInfo = {
  /// Linux-specific symbol version table containing versions required to link.
  VersionTable: Map<uint16, string>
  /// A mapping from a section number to the corresponding symbol table.
  SecNumToSymbTbls: Map<int, ELFSymbol []>
  /// Address to symbol mapping.
  AddrToSymbTable: Map<Addr, ELFSymbol>
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

/// CIE. Common Information Entry.
type CommonInformationEntry = {
  Version: uint8
  AugmentationString: string
  CodeAlignmentFactor: uint64
  DataAlignmentFactor: int64
  ReturnAddressRegister: uint64
  AugmentationData: byte [] option
  FDEEncoding: ExceptionHeaderValue
  FDEApplication: ExceptionHeaderApplication
}

/// FDE. Frame Description Entry.
type FrameDescriptionEntry = {
  PCBegin: Addr
  PCEnd: Addr
}

/// The main information block of .eh_frame.
type CallFrameInformation = {
  CIERecord: CommonInformationEntry
  FDERecord: FrameDescriptionEntry []
}

/// Main ELF format representation.
type ELF = {
  /// ELF header.
  ELFHdr: ELFHeader
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
  PLT: ARMap<ELFSymbol>
  /// Global symbols (such as R_X86_64_GLOB_DAT).
  Globals: Map<Addr, ELFSymbol>
  /// Exception frame.
  ExceptionFrame: CallFrameInformation list
  /// Invalid address ranges.
  InvalidAddrRanges: IntervalSet
  /// Not-in-file address ranges.
  NotInFileRanges: IntervalSet
  /// Executable address ranges.
  ExecutableRanges: IntervalSet
  /// BinReader
  BinReader: BinReader
}
