(*
  B2R2 - the Next-Generation Reversing Platform

  Author: DongYeop Oh <oh51dy@kaist.ac.kr>
          Sang Kil Cha <sangkilc@kaist.ac.kr>

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

module internal B2R2.BinFile.ELF

open System
open B2R2
open B2R2.Monads.Maybe
open B2R2.BinFile.FileHelper
open B2R2.BinFile

let secINIT = ".init"
let secPLT = ".plt"
let secTEXT = ".text"
let secFINI = ".fini"

let ELF_MIPS_ARCH = 0xf0000000u

let secStrings = [
  secINIT
  secPLT
  secTEXT
  secFINI
]
let elfMagicNumber = [| 0x7fuy; 0x45uy; 0x4cuy; 0x46uy |]
let pltThumbStubBytes = [| 0x78uy; 0x47uy; 0xc0uy; 0x46uy |]

type ELFFileType =
  | ETNone
  | Relocatable
  | Executable
  | SharedObject
  | Core

type OSABI =
  | ABISystemV
  | ABIHPUX
  | ABINetBSD
  | ABILinux
  | ABISolaris
  | ABIAIX
  | ABIIRIX
  | ABIFreeBSD
  | ABIEtc

type ELFHeader = {
  Class          : WordSize
  Endian         : Endian
  Version        : uint32
  OSABI          : OSABI
  OSABIVersion   : uint32
  ELFFileType    : ELFFileType
  MachineType    : Architecture
  EntryPoint     : uint64
  PHdrTblOffset  : uint64
  SHdrTblOffset  : uint64
  ELFFlags       : uint32
  HeaderSize     : uint16
  PHdrEntrySize  : uint16
  PHdrNum        : uint16
  SHdrEntrySize  : uint16
  SHdrNum        : uint16
  SHdrStrIdx     : uint16
}

/// This member categorizes the section's contents and semantics.
type SectionType =
  | SHTNull
  | SHTProgBits
  | SHTSymTab
  | SHTStrTab
  | SHTRela
  | SHTHash
  | SHTDynamic
  | SHTNote
  | SHTNoBits
  | SHTRel
  | SHTShLib
  | SHTDynSym
  | SHTInitArray
  | SHTFiniArray
  | SHTPreInitArray
  | SHTGroup
  | SHTSymTabShIdx
  | SHTLoProc
  | SHTARMExIdx
  | SHTARMPreMap
  | SHTARMAttr
  | SHTARMDebug
  | SHTARMOverlay
  | SHTMIPSRegInfo
  | SHTMIPSOptions
  | SHTMIPSABIFlags
  | SHTHiProc
  | SHTLoUser
  | SHTHiUser
  | SHTGNUAttributes
  | SHTGNUHash
  | SHTGNULibList
  | SHTGNUVerDef
  | SHTGNUVerNeed
  | SHTGNUVerSym

/// Sections support 1-bit flags that describe miscellaneous attributes.
[<FlagsAttribute>]
type SectionFlag =
  | SHFWrite            = 0x1UL
  | SHFAlloc            = 0x2UL
  | SHFExecInstr        = 0x4UL
  | SHFMerge            = 0x10UL
  | SHFString           = 0x20UL
  | SHFInfoLink         = 0x40UL
  | SHFLinkOrder        = 0x80UL
  | SHFOSNonConforming  = 0x100UL
  | SHFGroup            = 0x200UL
  | SHFTLS              = 0x400UL
  | SHFCompressed       = 0x800UL
  | SHFMaskOS           = 0x0ff00000UL
  | SHFMaskProc         = 0xf0000000UL
  | SHFOrdered          = 0x40000000UL
  | SHFExclude          = 0x80000000UL
  | SHFX8664Large       = 0x10000000UL

/// ELF Section
type ELFSection = {
  /// Unique section number.
  SecNum        : int
  /// The name of the section.
  SecName       : string
  /// Categorizes the section's contents and semantics.
  SecType       : SectionType
  SecFlags      : SectionFlag
  SecAddr       : Addr
  SecOffset     : uint64
  /// The section's size in bytes.
  SecSize       : uint64
  /// A section header table index link.
  SecLink       : uint32
  /// Extra information.
  SecInfo       : uint32
  SecAlignment  : uint64
  /// Some sections hold a table of fixed-size entries, such as a symbol
  /// table. For such a section, this member gives the size in bytes of each
  /// entry.
  SecEntrySize  : uint64
}

type SectionTbl = {
  SecByAddr     : ARMap<ELFSection>
  SecByType     : Map<SectionType, ELFSection>
  SecByName     : Map<string, ELFSection>
  SecByNum      : ELFSection []
}

/// A symbol's binding determines the linkage visibility and behavior.
type ELFSymbolBind =
  | STBLocal
  | STBGlobal
  | STBWeak
  | STBLoOS
  | STBHiOS
  | STBLoProc
  | STBHiProc

/// A symbol's type provides a general classification for the associated entity.
type ELFSymbolType =
  | STTNoType
  | STTObject
  | STTFunc
  | STTSection
  | STTFile
  | STTCommon
  | STTTLS
  | STTReloc
  | STTSReloc
  | STTLoOS
  | STTHiOS
  | STTLoProc
  | STTHiProc

/// This member currently specifies a symbol's visibility
type ELFSymbolVisibility =
  | STVDefault
  | STVInternal
  | STVHidden
  | STVProtected

/// Every symbol table entry is defined in relation to some section.
/// This member holds the relevant section header table index.
type ELFSymbolIdx =
  | SHNUndef
  | SHNLoReserve
  | SHNLoProc
  | SHNHiProc
  | SHNLoOS
  | SHNHiOS
  | SHNABS
  | SHNCommon
  | SHNXIndex
  | SHNHiReserve
  | SecIdx of int

type VersionInfo =
  | SYMUndefined
  | SYMHidden
  | SYMPublic

type SymVerInfo = {
  VerInfo : VersionInfo
  VerName : string
  Other   : uint16 option
}

type ELFSymbol = {
  SymNum         : uint64
  Addr           : Addr
  SymName        : string
  Size           : uint64
  SymType        : ELFSymbolType
  Bind           : ELFSymbolBind
  Vis            : ELFSymbolVisibility
  Ndx            : ELFSymbolIdx
  ParentSection  : ELFSection option
  VerInfo        : SymVerInfo option
}
/// This structure appears in a SHT_GNU_verdef section.
type VerDefAux = {
  /// Version index.
  Idx         : uint16
  /// Offset to verdaux entries.
  EntryOffset : int
  /// Offset to next verdef.
  Next        : int
}

type VerNeedAux = {
  VnaOther    : uint16
  /// String table offset to version name.
  NameOffset  : int
  /// Offset to next vernaux.
  Next        : int
}

type Relocation = {
  RelOffset   : uint64
  RelSecName  : string
  RelInfo     : uint64
  RelELFSymbol   : ELFSymbol
  RelAddend   : uint64
}

type RelocInfo = {
  RelocByAddr  : Map<Addr, Relocation>
  RelocByName  : Map<string, Relocation>
}

type SymChunk =
  {
    /// Section symbol.
    SecELFSymbol     : ELFSymbol option
    /// Function symbol.
    FuncELFSymbol    : ELFSymbol option
    /// Mapping symbols are used specifically for ARM to specify code/data
    /// boundaries. For example, $a represents the start of an ARM code snippet.
    MappingELFSymbol : ELFSymbol option
  }

type ELFSymbolInfo = {
  /// DynSymArr stores dynamic symbols based on the symbol number, which is a
  /// unique number used to refer to a symbol entry in ELF dynamic symbol table.
  DynSymArr          : ELFSymbol []
  /// StaticSymArr stores static symbols based on the symbol number.
  StaticSymArr       : ELFSymbol []
  /// We call a sequence of instructions/values that has the same symbol name
  /// as a "symbol chunk". ELFSymbol chunks are only relevant to code/data symbols.
  SymChunks          : ARMap<SymChunk>
  /// Store a mapping from AddrRange to a mapping symbol (for ARM binaries).
  MappingELFSymbols  : ARMap<ELFSymbol>
  /// Relocation information.
  RelocInfo          : RelocInfo
  /// Procedure Linkage Table.
  PLT                : ARMap<ELFSymbol>
  /// PLT start address.
  PLTStart           : Addr
  /// PLT end address.
  PLTEnd             : Addr
}

/// This member tells what kind of segment this array element describes or
/// how to interpret the array element's information. A segment is also known as
/// a 'program header'.
type ProgramHeaderType =
  | PHTNull
  | PHTLoad
  | PHTDynamic
  | PHTInterp
  | PHTNote
  | PHTShLib
  | PHTPhdr
  | PHTTLS
  | PHTLoOS
  | PHTHiOS
  | PHTLoProc
  | PHTARMExIdx
  | PHTMIPSABIFlags
  | PHTHiProc
  | PHTGNUEHFrame
  | PHTGNUStack
  | PHTGNURelro
  | PHTPAXFlags

/// An executable or shared object file's program header table is an array of
/// structures, each of which describes a segment or the other information a
/// system needs to prepare for execution. An object file segment contains one
/// or more sections. Program headers are meaningful only for executable and
/// shared object files. A file specifies its own program header size with
/// the ELF header's members.
type ProgramHeader = {
  PHType       : ProgramHeaderType
  PHFlags      : int
  PHOffset     : uint64
  PHAddr       : Addr
  PHPhyAddr    : Addr
  PHFileSize   : uint64
  PHMemSize    : uint64
  PHAlignment  : uint64
}

type ELF = {
  ELFHdr            : ELFHeader
  Segments          : ProgramHeader list
  LoadableSegments  : ProgramHeader list
  LoadableSecNums   : Set<int>
  Sections          : SectionTbl
  SymInfo           : ELFSymbolInfo
}

let elfTypeToSymbKind ndx = function
  | STTObject -> SymbolKind.ObjectType
  | STTFunc ->
    if ndx = SHNUndef then SymbolKind.NoType
    elif ndx = SHNCommon then SymbolKind.ExternFunctionType
    else SymbolKind.FunctionType
  | STTSection -> SymbolKind.SectionType
  | STTFile ->SymbolKind.FileType
  | _ -> SymbolKind.NoType

let elfVersionToLibName version =
  match version with
  | Some version -> version.VerName
  | None -> ""

let isELFHeader (reader: BinReader) offset =
  reader.PeekBytes (4, offset) = elfMagicNumber

let readClass (reader: BinReader) offset =
  let classOffset = 4
  match offset + classOffset |> reader.PeekByte with
  | 0x1uy -> WordSize.Bit32
  | 0x2uy -> WordSize.Bit64
  | c -> failwithf "invalid class type (%02x)" c

/// Return the endianness from the ELF file starting at the offset.
let readEndianness (reader: BinReader) offset =
  let endianOffset = 5
  match offset + endianOffset |> reader.PeekByte with
  | 0x1uy -> Endian.Little
  | 0x2uy -> Endian.Big
  | c -> failwithf "invalid endian type (%02x)" c

let readVersion (reader: BinReader) offset =
  let versionOffset = 6
  offset + versionOffset |> reader.PeekByte |> uint32

let readOSABI (reader: BinReader) offset =
  let osabiOffset = 7
  match offset + osabiOffset |> reader.PeekByte with
  | 0x0uy -> ABISystemV
  | 0x1uy -> ABIHPUX
  | 0x2uy -> ABINetBSD
  | 0x3uy -> ABILinux
  | 0x6uy -> ABISolaris
  | 0x7uy -> ABIAIX
  | 0x8uy -> ABIIRIX
  | 0x9uy -> ABIFreeBSD
  | _ -> ABIEtc

let readOSABIVersion (reader: BinReader) offset =
  let osabiVersionOffset = 8
  offset + osabiVersionOffset |> reader.PeekByte |> uint32

let readELFFileType (reader: BinReader) offset =
  let elfFileTypeOffset = 16
  match offset + elfFileTypeOffset |> reader.PeekUInt16 with
  | 0x0us -> ETNone
  | 0x1us -> Relocatable
  | 0x2us -> Executable
  | 0x3us -> SharedObject
  | 0x4us -> Core
  | t -> failwithf "invalid file type (%02x)" t

let readEntryPoint (reader: BinReader) cls offset =
  let entryPointOffset = 24
  offset + entryPointOffset |> peekUIntOfType reader cls

let readPHdrTableOffset (reader: BinReader) cls offset =
  let programHeaderOffset = if cls = WordSize.Bit32 then 28 else 32
  offset + programHeaderOffset |> peekUIntOfType reader cls

let readSHdrTableOffset (reader: BinReader) cls offset =
  let sectionHeaderOffset = if cls = WordSize.Bit32 then 32 else 40
  offset + sectionHeaderOffset |> peekUIntOfType reader cls

let readEFlags (reader: BinReader) cls offset =
  let elfFlagsOffset = if cls = WordSize.Bit32 then 36 else 48
  offset + elfFlagsOffset |> reader.PeekUInt32

let readHeaderSize (reader: BinReader) cls offset =
  let headerSizeOffset = if cls = WordSize.Bit32 then 40 else 52
  offset + headerSizeOffset |> reader.PeekUInt16

let readPHdrEntrySize (reader: BinReader) cls offset =
  let pHdrEntrySizeOffset = if cls = WordSize.Bit32 then 42 else 54
  offset + pHdrEntrySizeOffset |> reader.PeekUInt16

let readPHdrNum (reader: BinReader) cls offset =
  let pHdrEntrySizeOffset = if cls = WordSize.Bit32 then 44 else 56
  offset + pHdrEntrySizeOffset |> reader.PeekUInt16

let readSHdrEntrySize (reader: BinReader) cls offset =
  let sHdrEntrySizeOffset = if cls = WordSize.Bit32 then 46 else 58
  offset + sHdrEntrySizeOffset |> reader.PeekUInt16

let readSHdrNum (reader: BinReader) cls offset =
  let pHdrEntrySizeOffset = if cls = WordSize.Bit32 then 48 else 60
  offset + pHdrEntrySizeOffset |> reader.PeekUInt16

let readSHdrStrIdx (reader: BinReader) cls offset =
  let pHdrEntrySizeOffset = if cls = WordSize.Bit32 then 50 else 62
  offset + pHdrEntrySizeOffset |> reader.PeekUInt16

let getMIPSISA (reader: BinReader) cls offset =
  match readEFlags reader cls offset &&& ELF_MIPS_ARCH with
  | 0x00000000u -> Arch.MIPS1
  | 0x10000000u -> Arch.MIPS2
  | 0x20000000u -> Arch.MIPS3
  | 0x30000000u -> Arch.MIPS4
  | 0x40000000u -> Arch.MIPS5
  | 0x50000000u -> Arch.MIPS32
  | 0x60000000u -> Arch.MIPS64
  | 0x70000000u -> Arch.MIPS32R2
  | 0x80000000u -> Arch.MIPS64R2
  | 0x90000000u -> Arch.MIPS32R6
  | 0xa0000000u -> Arch.MIPS64R6
  | c -> failwithf "invalid MIPS arch (%02x)" c

let readArch (reader: BinReader) cls offset =
  let archOffset = 18
  match offset + archOffset |> reader.PeekInt16 with
  | 0x03s -> Arch.IntelX86
  | 0x3es -> Arch.IntelX64
  | 0x28s -> Arch.ARMv7
  | 0xB7s -> Arch.AARCH64
  | 0x08s | 0x0as -> getMIPSISA reader cls offset
  | _ -> Arch.UnknownISA

let parseELFHeader (reader: BinReader) offset =
  let cls = readClass reader offset
  {
    Class = cls
    Endian = readEndianness reader offset
    Version = readVersion reader offset
    OSABI = readOSABI reader offset
    OSABIVersion = readOSABIVersion reader offset
    ELFFileType = readELFFileType reader offset
    MachineType = readArch reader cls offset
    EntryPoint = readEntryPoint reader cls offset
    PHdrTblOffset = readPHdrTableOffset reader cls offset
    SHdrTblOffset = readSHdrTableOffset reader cls offset
    ELFFlags = readEFlags reader cls offset
    HeaderSize = readHeaderSize reader cls offset
    PHdrEntrySize = readPHdrEntrySize reader cls offset
    PHdrNum = readPHdrNum reader cls offset
    SHdrEntrySize = readSHdrEntrySize reader cls offset
    SHdrNum = readSHdrNum reader cls offset
    SHdrStrIdx = readSHdrStrIdx reader cls offset
  }

/// Return the raw memory contents that represent the section names separated by
/// null character.
let parseSectionNameBytes eHdr (reader: BinReader) =
  let offset =
    eHdr.SHdrTblOffset + uint64 (eHdr.SHdrStrIdx * eHdr.SHdrEntrySize)
  let padding = (8 + (WordSize.toByteWidth eHdr.Class * 2))
  let offset = Convert.ToInt32 offset + padding
  let struct (strOffset, nextOffset) = readUIntOfType reader eHdr.Class offset
  let size = peekUIntOfType reader eHdr.Class nextOffset
  reader.PeekBytes (Convert.ToInt32 size, Convert.ToInt32 strOffset)

let readSecName (reader: BinReader) strBytes offset =
  offset |> reader.PeekInt32 |> ByteArray.extractCString strBytes

let readSecType (reader: BinReader) offset =
  let secTypeOffset = 4
  match offset + secTypeOffset |> reader.PeekUInt32 with
  | 0x00u -> SHTNull
  | 0x01u -> SHTProgBits
  | 0x02u -> SHTSymTab
  | 0x03u -> SHTStrTab
  | 0x04u -> SHTRela
  | 0x05u -> SHTHash
  | 0x06u -> SHTDynamic
  | 0x07u -> SHTNote
  | 0x08u -> SHTNoBits
  | 0x09u -> SHTRel
  | 0x0au -> SHTShLib
  | 0x0bu -> SHTDynSym
  | 0x0eu -> SHTInitArray
  | 0x0fu -> SHTFiniArray
  | 0x10u -> SHTPreInitArray
  | 0x11u -> SHTGroup
  | 0x12u -> SHTSymTabShIdx
  | 0x70000000u -> SHTLoProc
  | 0x70000001u -> SHTARMExIdx
  | 0x70000002u -> SHTARMPreMap
  | 0x70000003u -> SHTARMAttr
  | 0x70000004u -> SHTARMDebug
  | 0x70000005u -> SHTARMOverlay
  | 0x70000006u -> SHTMIPSRegInfo
  | 0x7000000du -> SHTMIPSOptions
  | 0x7000002au -> SHTMIPSABIFlags
  | 0x80000000u -> SHTLoUser
  | 0xffffffffu -> SHTHiUser
  | 0x6ffffff5u -> SHTGNUAttributes
  | 0x6ffffff6u -> SHTGNUHash
  | 0x6ffffff7u -> SHTGNULibList
  | 0x6ffffffdu -> SHTGNUVerDef
  | 0x6ffffffeu -> SHTGNUVerNeed
  | 0x6fffffffu -> SHTGNUVerSym
  | t -> failwithf "Invalid section type (%02x)" t

let readSecFlags (reader: BinReader) cls offset : SectionFlag =
  let secFlagsOffset = 8
  offset + secFlagsOffset
  |> peekUIntOfType reader cls
  |> LanguagePrimitives.EnumOfValue

let readSecAddr (reader: BinReader) cls offset =
  let secAddrOffset = if cls = WordSize.Bit32 then 12 else 16
  offset + secAddrOffset |> peekUIntOfType reader cls

let readSecOffset (reader: BinReader) cls offset =
  let offsetOfSecOffset = if cls = WordSize.Bit32 then 16 else 24
  offset + offsetOfSecOffset |> peekUIntOfType reader cls

let readSecSize (reader: BinReader) cls offset =
  let secSizeOffset = if cls = WordSize.Bit32 then 20 else 32
  offset + secSizeOffset |> peekUIntOfType reader cls

let readSecLink (reader: BinReader) cls offset =
  let secLinkOffset = if cls = WordSize.Bit32 then 24 else 40
  offset + secLinkOffset |> reader.PeekUInt32

let readSecInfo (reader: BinReader) cls offset =
  let secInfoOffset = if cls = WordSize.Bit32 then 28 else 44
  offset + secInfoOffset |> reader.PeekUInt32

let readSecAlign (reader: BinReader) cls offset =
  let secAlignOffset = if cls = WordSize.Bit32 then 32 else 48
  offset + secAlignOffset |> peekUIntOfType reader cls

let readSecEntrySize (reader: BinReader) cls offset =
  let secEntrySizeOffset = if cls = WordSize.Bit32 then 36 else 56
  offset + secEntrySizeOffset |> peekUIntOfType reader cls

let parseSection num strBytes cls reader offset =
  {
    SecNum = num
    SecName = readSecName reader strBytes offset
    SecType = readSecType reader offset
    SecFlags = readSecFlags reader cls offset
    SecAddr = readSecAddr reader cls offset
    SecOffset = readSecOffset reader cls offset
    SecSize = readSecSize reader cls offset
    SecLink = readSecLink reader cls offset
    SecInfo = readSecInfo reader cls offset
    SecAlignment = readSecAlign reader cls offset
    SecEntrySize = readSecEntrySize reader cls offset
  }

let inline hasSHFTLS flags =
  flags &&& SectionFlag.SHFTLS = SectionFlag.SHFTLS

let inline hasSHFAlloc flags =
  flags &&& SectionFlag.SHFAlloc = SectionFlag.SHFAlloc

let nextSecOffset cls offset =
  offset + if cls = WordSize.Bit32 then 40 else 64

let foldSection (secByAddr, secByType, secByName, lst) sec =
  let secByType = Map.add sec.SecType sec secByType
  let secByName = Map.add sec.SecName sec secByName
  let secByAddr =
    (* .tbss has a meaningless virtual address as per
       https://stackoverflow.com/questions/25501044/. *)
    let secEndAddr = sec.SecAddr + sec.SecSize
    if sec.SecAddr = 0x00UL ||
       hasSHFTLS sec.SecFlags ||
       secEndAddr <= sec.SecAddr then secByAddr
    else let endAddr = sec.SecAddr + sec.SecSize
         ARMap.addRange sec.SecAddr endAddr sec secByAddr
  (secByAddr, secByType, secByName, sec :: lst)

let parseSectionsFromEHdr eHdr reader =
  let rec parseLoop nameBytes sIdx acc offset =
    if int eHdr.SHdrNum = sIdx then acc
    else
      let sec = parseSection sIdx nameBytes eHdr.Class reader offset
      let nextOffset = nextSecOffset eHdr.Class offset
      parseLoop nameBytes (sIdx + 1) (foldSection acc sec) nextOffset
  let nameBytes = parseSectionNameBytes eHdr reader
  let offset = Convert.ToInt32 eHdr.SHdrTblOffset
  let acc = ARMap.empty, Map.empty, Map.empty, []
  let addrMap, typeMap, nameMap, secs = parseLoop nameBytes 0 acc offset
  {
    SecByAddr = addrMap
    SecByType = typeMap
    SecByName = nameMap
    SecByNum = List.rev secs |> Array.ofList
  }

/// PHTTLS segment contains only SHFTLS sections, PHTPhdr no sections at all.
/// TLS sections is contained only in PHTTLS, PHTGNURelro and PHTLoad.
let checkSHFTLS pHdr sec =
  let checkTLS = hasSHFTLS sec.SecFlags
  let checkPtypeWithoutTLS = function
    | PHTTLS | PHTPhdr -> false
    | _ -> true
  let checkPtypeWithinTLS = function
    | PHTTLS | PHTGNURelro | PHTLoad -> true
    | _ -> false
  let chkCaseOfwithoutSHFTLS = not checkTLS && checkPtypeWithoutTLS pHdr.PHType
  let chkCaseOfWithinSHFTLS = checkTLS && checkPtypeWithinTLS pHdr.PHType
  chkCaseOfWithinSHFTLS || chkCaseOfwithoutSHFTLS

/// PHTLoad, PHTDynamic, PHTGNUEHFrame, PHTGNURelro and PHTGNUStack segment
/// contain only SHFAlloc sections.
let checkSHFAlloc pHdr sec =
  let checkPtype = function
    | PHTLoad | PHTDynamic | PHTGNUEHFrame | PHTGNURelro | PHTGNUStack -> true
    | _ -> false
  (hasSHFAlloc sec.SecFlags |> not && checkPtype pHdr.PHType) |> not

let checkSecOffset isNoBits secSize pHdr sec =
  let pToSOffset = sec.SecOffset - pHdr.PHOffset
  isNoBits || (sec.SecOffset >= pHdr.PHOffset
  && pToSOffset < pHdr.PHFileSize
  && pToSOffset + secSize <= pHdr.PHFileSize)

let checkVMA secSize pHdr sec =
  let progToSec = sec.SecAddr - pHdr.PHAddr
  (* Check if the section is in the range of the VMA (program header) *)
  let inRange = sec.SecAddr >= pHdr.PHAddr
                && progToSec < pHdr.PHMemSize
                && progToSec + secSize <= pHdr.PHMemSize
  (hasSHFAlloc sec.SecFlags |> not) || inRange

let checkDynamicProc isNoBits pHdr sec =
  let pToSOffset = sec.SecOffset - pHdr.PHOffset
  let checkOff = sec.SecOffset > pHdr.PHOffset && pToSOffset < pHdr.PHFileSize
  let checkALLOC = hasSHFAlloc sec.SecFlags |> not
  let progToSec = sec.SecAddr - pHdr.PHAddr
  let checkMem = sec.SecAddr > pHdr.PHAddr && progToSec < pHdr.PHMemSize
  let checkDynSize = (isNoBits || checkOff) && (checkALLOC || checkMem)
  let checkSizeZero = sec.SecSize <> 0UL || pHdr.PHMemSize = 0UL
  pHdr.PHType <> PHTDynamic || checkSizeZero || checkDynSize

let isTbss isNoBits pHdr sec =
  hasSHFTLS sec.SecFlags && isNoBits && pHdr.PHType <> PHTTLS

/// Check if a section can be included in the program header, i.e., loaded in
/// memory when executed. The logic here is derived from OBJDUMP code.
let isSecInPHdr pHdr sec =
  let isNoBits = sec.SecType = SHTNoBits
  let isTbss = isTbss isNoBits pHdr sec
  let secSize = if isTbss then 0UL else sec.SecEntrySize
  checkSHFTLS pHdr sec
  && checkSHFAlloc pHdr sec
  && checkSecOffset isNoBits secSize pHdr sec
  && checkVMA secSize pHdr sec
  && checkDynamicProc isNoBits pHdr sec
  && not isTbss

let gatherLoadlabeSecNums pHdr secs =
  let foldSHdr acc sec =
    let lb = pHdr.PHOffset
    let ub = lb + pHdr.PHFileSize
    if sec.SecOffset >= lb && sec.SecOffset < ub then sec.SecNum :: acc else acc
  ARMap.fold (fun acc _ s -> foldSHdr acc s) [] secs.SecByAddr

let readPHdrType (reader: BinReader) offset =
  match reader.PeekUInt32 offset with
  | 0x00u -> PHTNull
  | 0x01u -> PHTLoad
  | 0x02u -> PHTDynamic
  | 0x03u -> PHTInterp
  | 0x04u -> PHTNote
  | 0x05u -> PHTShLib
  | 0x06u -> PHTPhdr
  | 0x07u -> PHTTLS
  | 0x60000000u -> PHTLoOS
  | 0x6fffffffu -> PHTHiOS
  | 0x70000000u -> PHTLoProc
  | 0x70000001u -> PHTARMExIdx
  | 0x70000003u -> PHTMIPSABIFlags
  | 0x7fffffffu -> PHTHiProc
  | 0x6474e550u -> PHTGNUEHFrame
  | 0x6474e551u -> PHTGNUStack
  | 0x6474e552u -> PHTGNURelro
  | 0x65041580u -> PHTPAXFlags
  | t -> failwithf "invalid Program Types type (%02x)" t

let readPHdrFlags (reader: BinReader) cls offset =
  let pHdrPHdrFlagsOffset = if cls = WordSize.Bit32 then 24 else 4
  offset + pHdrPHdrFlagsOffset |> reader.PeekInt32

let readPHdrOffset (reader: BinReader) cls offset =
  let offsetOfPHdrOffset = if cls = WordSize.Bit32 then 4 else 8
  offset + offsetOfPHdrOffset |> peekUIntOfType reader cls

let readPHdrAddr (reader: BinReader) cls offset =
  let pHdrAddrOffset = if cls = WordSize.Bit32 then 8 else 16
  offset + pHdrAddrOffset |> peekUIntOfType reader cls

let readPHdrPhyAddr (reader: BinReader) cls offset =
  let pHdrPhyAddrOffset = if cls = WordSize.Bit32 then 12 else 24
  offset + pHdrPhyAddrOffset |> peekUIntOfType reader cls

let readPHdrFileSize (reader: BinReader) cls offset =
  let pHdrPHdrFileSizeOffset = if cls = WordSize.Bit32 then 16 else 32
  offset + pHdrPHdrFileSizeOffset |> peekUIntOfType reader cls

let readPHdrMemSize (reader: BinReader) cls offset =
  let pHdrPHdrMemSizeOffset = if cls = WordSize.Bit32 then 20 else 40
  offset + pHdrPHdrMemSizeOffset |> peekUIntOfType reader cls

let readPHdrAlign (reader: BinReader) cls offset =
  let pHdrPHdrAlignOffset = if cls = WordSize.Bit32 then 28 else 48
  offset + pHdrPHdrAlignOffset |> peekUIntOfType reader cls

let parseProgHeader cls (reader: BinReader) offset =
  {
    PHType = readPHdrType reader offset
    PHFlags = readPHdrFlags reader cls offset
    PHOffset = readPHdrOffset reader cls offset
    PHAddr = readPHdrAddr reader cls offset
    PHPhyAddr = readPHdrPhyAddr reader cls offset
    PHFileSize = readPHdrFileSize reader cls offset
    PHMemSize = readPHdrMemSize reader cls offset
    PHAlignment = readPHdrAlign reader cls offset
  }

let nextPHdrOffset cls offset =
  offset + if cls = WordSize.Bit32 then 32 else 56

/// Parse and associate program headers with section headers to return the list
/// of segments.
let parseProgHeaders eHdr reader =
  let rec parseLoop pNum acc offset =
    if pNum = 0us then List.rev acc
    else
      let phdr = parseProgHeader eHdr.Class reader offset
      parseLoop (pNum - 1us) (phdr :: acc) (nextPHdrOffset eHdr.Class offset)
  Convert.ToInt32 eHdr.PHdrTblOffset
  |> parseLoop eHdr.PHdrNum []

let computeLoadableSecNums secs segs =
  let loop set seg =
    gatherLoadlabeSecNums seg secs
    |> List.fold (fun set n -> Set.add n set) set
  segs |> List.fold loop Set.empty

let readRelOffset (reader: BinReader) cls offset =
  peekUIntOfType reader cls offset

let readRelInfo (reader: BinReader) cls offset =
  let relInfoOffset = if cls = WordSize.Bit32 then 4 else 8
  offset + relInfoOffset |> peekUIntOfType reader cls

let readRelAddend (reader: BinReader) isRel cls offset =
  let relAddendOffset = if cls = WordSize.Bit32 then 8 else 16
  if isRel then 0UL else offset + relAddendOffset  |> peekUIntOfType reader cls

let nextRelOffset isRel cls offset =
  match isRel with
  | true when cls = WordSize.Bit32 -> 8 + offset
  | true -> 16 + offset
  | false when cls = WordSize.Bit32 -> 12 + offset
  | false -> 24 + offset

let readInfoWithArch reader eHdr offset =
  let info = readRelInfo reader eHdr.Class offset
  match eHdr.MachineType with
  | Arch.MIPS1 | Arch.MIPS2 | Arch.MIPS3 | Arch.MIPS4 | Arch.MIPS5
  | Arch.MIPS32 | Arch.MIPS32R2 | Arch.MIPS32R6
  | Arch.MIPS64 | Arch.MIPS64R2 | Arch.MIPS64R6 ->
    if eHdr.Endian = Endian.Little then
      (info &&& 0xffffffffUL) <<< 32
      ||| (info >>> 56) &&& 0xffUL
      ||| (info >>> 40) &&& 0xff00UL
      ||| (info >>> 24) &&& 0xff000000UL
      ||| (info >>> 8) &&& 0xff00000000UL
    else info
  | _ -> info

let parseRelocELFSymbol isRel eHdr (dSym: ELFSymbol []) sec reader offset =
  let getRelocSIdx i = if eHdr.Class = WordSize.Bit32 then i >>> 8 else i >>> 32
  let relOffset = readRelOffset reader eHdr.Class offset
  let info = readInfoWithArch reader eHdr offset
  let addend = readRelAddend reader isRel eHdr.Class offset
  let sym = dSym.[(getRelocSIdx info |> Convert.ToInt32)]
  {
    RelOffset = relOffset
    RelSecName = sec.SecName
    RelInfo = info
    RelELFSymbol = sym
    RelAddend = addend
  }

let foldRelocation relInfo rel =
  {
    RelocByAddr = Map.add rel.RelOffset rel relInfo.RelocByAddr
    RelocByName = Map.add rel.RelELFSymbol.SymName rel relInfo.RelocByName
  }

let relRelocs eHdr (reader: BinReader) sec dynSym relInfo offset =
  let rec parseRelMap rNum isRel relInfo offset =
    if rNum = 0UL then relInfo
    else let rel = parseRelocELFSymbol isRel eHdr dynSym sec reader offset
         let nextOffset = nextRelOffset isRel eHdr.Class offset
         parseRelMap (rNum - 1UL) isRel (foldRelocation relInfo rel) nextOffset
  let isRel = sec.SecType = SHTRel
  let len = if isRel then (uint64 <| WordSize.toByteWidth eHdr.Class * 2)
            else (uint64 <| WordSize.toByteWidth eHdr.Class * 3)
  parseRelMap (sec.SecSize / len) isRel relInfo offset

let parseRelocation eHdr secs (dynSym: ELFSymbol []) reader =
  let parseRelMap acc sec =
    let invaldSecType = sec.SecType <> SHTRela && sec.SecType <> SHTRel
    if invaldSecType || sec.SecSize = 0UL || dynSym.Length = 0 then acc
    else relRelocs eHdr reader sec dynSym acc (Convert.ToInt32 sec.SecOffset)
  let emptyRelInfo =
    {
      RelocByAddr = Map.empty
      RelocByName = Map.empty
    }
  Array.fold parseRelMap emptyRelInfo secs.SecByNum

let readSymNameIdx (reader: BinReader) offset =
  reader.PeekUInt32 offset

let readSymInfo (reader: BinReader) cls offset =
  let symInfoOffset = if cls = WordSize.Bit32 then 12 else 4
  offset + symInfoOffset |> reader.PeekByte

let readSymOther (reader: BinReader) cls offset =
  let symOtherOffset = if cls = WordSize.Bit32 then 13 else 5
  offset + symOtherOffset |> reader.PeekByte

let readSymNdx (reader: BinReader) cls offset =
  let symNdxOffset = if cls = WordSize.Bit32 then 14 else 6
  offset + symNdxOffset |> reader.PeekUInt16 |> int

let getSHNdx = function
 | 0x00 -> SHNUndef
 | 0xff00 -> SHNLoReserve
 | 0xfff1 -> SHNABS
 | 0xfff2 -> SHNCommon
 | n -> SecIdx n

let readSymAddr (reader: BinReader) cls offset =
  let symAddrOffset = if cls = WordSize.Bit32 then 4 else 8
  offset + symAddrOffset |> peekUIntOfType reader cls

let readSymSize (reader: BinReader) cls offset =
  let symSizeOffset = if cls = WordSize.Bit32 then 8 else 16
  offset + symSizeOffset |> peekUIntOfType reader cls

let getSTBind = function
  | 0x00uy -> STBLocal
  | 0x01uy -> STBGlobal
  | 0x02uy -> STBWeak
  | 0x0auy -> STBLoOS
  | 0x0cuy -> STBHiOS
  | 0x0duy -> STBLoProc
  | 0x0fuy -> STBHiProc
  | b -> failwithf "invalid ELFSymbol bind (%02x)" b

let getSTType = function
  | 0x00uy -> STTNoType
  | 0x01uy -> STTObject
  | 0x02uy -> STTFunc
  | 0x03uy -> STTSection
  | 0x04uy -> STTFile
  | 0x05uy -> STTCommon
  | 0x06uy -> STTTLS
  | 0x08uy -> STTReloc
  | 0x09uy -> STTSReloc
  | 0x0auy -> STTLoOS
  | 0x0cuy -> STTHiOS
  | 0x0duy -> STTLoProc
  | 0x0fuy -> STTHiProc
  | t -> failwithf "invalid ELFSymbol Type (%02x)" t

let getSTVis = function
  | 0x00uy -> STVDefault
  | 0x01uy -> STVInternal
  | 0x02uy -> STVHidden
  | 0x03uy -> STVProtected
  | v -> failwithf "invalid ELFSymbol visibility (%02x)" v

let getVerNeedInfo strTab versData vna =
  if vna.VnaOther = versData then
    let name = if vna.NameOffset >= Array.length strTab then ""
               else ByteArray.extractCString strTab vna.NameOffset
    Some { VerInfo = SYMUndefined; VerName = name; Other = Some vna.VnaOther }
  else None

let parseVerNeed (reader: BinReader) versData strTab verNeedSec =
  let rec getVerNeedAux offset =
    let aux = { VnaOther = reader.PeekUInt16 (offset + 6)
                NameOffset = reader.PeekInt32 (offset + 8)
                Next = reader.PeekInt32 (offset + 12) }
    if aux.VnaOther = versData || aux.Next = 0 then aux
    else getVerNeedAux (offset + aux.Next)
  let rec loop pos =
    let aux = getVerNeedAux (reader.PeekInt32 (pos + 8) + pos)
    let next = reader.PeekInt32 (pos + 12)
    if aux.VnaOther = versData || next = 0 then aux else loop (pos + next)
  verNeedSec.SecOffset
  |> Convert.ToInt32
  |> loop
  |> getVerNeedInfo strTab versData

let parseNeed secMap strTab reader versData =
  Map.tryFind SHTGNUVerNeed secMap
  >>= parseVerNeed reader versData strTab

let getVerDefInfo (reader: BinReader) nameIdx strTab versData offset =
  let idx = reader.PeekUInt16 offset |> int
  if nameIdx = uint32 idx then None
  else let info = if versData &&& 0x8000us = 0us then SYMPublic else SYMHidden
       let name = if idx >= Array.length strTab then ""
                  else ByteArray.extractCString strTab idx
       Some { VerInfo = info; VerName = name; Other = None }

let parseVerDef (reader: BinReader) versData nameIdx strTab verDefSec =
  let rec getVerDef pos =
    let aux = { Idx = reader.PeekUInt16 (pos + 4)
                EntryOffset = reader.PeekInt32 (pos + 12)
                Next = reader.PeekInt32 (pos + 16) }
    if aux.Idx = (versData &&& 0x7fffus) || aux.Next = 0 then struct (aux, pos)
    else getVerDef (pos + aux.Next)
  let struct (aux, pos) = verDefSec.SecOffset |> Convert.ToInt32 |> getVerDef
  if aux.Next = 0 then None
  else getVerDefInfo reader nameIdx strTab versData (pos + aux.EntryOffset)

let parseDef secMap strTab reader idx nameIdx versData =
  if idx <> SHNUndef && versData <> 0x8001us then
    Map.tryFind SHTGNUVerDef secMap
    >>= parseVerDef reader versData nameIdx strTab
  else None

let getVerInfo secMap symSec strTab (reader: BinReader) n idx nameIdx =
  let verSymSec = Map.tryFind SHTGNUVerSym secMap
  let parseVersData sec =
    let pos = sec.SecOffset + (n * 2UL) |> Convert.ToInt32
    let versData = reader.PeekUInt16 pos
    if (versData &&& 0x8000us <> 0us) || (versData > 1us) then Some versData
    else None
  let getInfo versData =
    Monads.OrElse.orElse {
      yield! parseNeed secMap strTab reader versData
      yield! parseDef secMap strTab reader idx nameIdx versData
    }
  (if symSec.SecType = SHTDynSym then verSymSec else None)
  >>= parseVersData >>= getInfo

let parseELFSymbol secs symSec strTab cls (reader: BinReader) n offset =
  let nameIdx = readSymNameIdx reader offset
  let info = readSymInfo reader cls offset
  let other = readSymOther reader cls offset
  let ndx =  readSymNdx reader cls offset
  let secIdx = getSHNdx ndx
  {
    SymNum = n
    Ndx = secIdx
    Addr = readSymAddr reader cls offset
    Size = readSymSize reader cls offset
    Bind = info >>> 4 |> getSTBind
    SymType = info &&& 0xfuy |> getSTType
    Vis = other &&& 0x3uy |> getSTVis
    ParentSection = Array.tryItem ndx secs.SecByNum
    SymName = ByteArray.extractCString strTab (Convert.ToInt32 nameIdx)
    VerInfo = getVerInfo secs.SecByType symSec strTab reader n secIdx nameIdx
  }

let nextSymOffset cls offset =
  offset + if cls = WordSize.Bit32 then 16 else 24

let parseELFSymbols cls secs (reader: BinReader) acc symSec =
  let rec sParse count sNum strTab acc offset =
    if count = sNum then List.rev acc
    else let sym = parseELFSymbol secs symSec strTab cls reader count offset
         let nextOffset = nextSymOffset cls offset
         sParse (count + 1UL) sNum strTab (sym :: acc) nextOffset
  let strHdr = secs.SecByNum.[Convert.ToInt32 symSec.SecLink]
  let strTab = reader.PeekBytes (Convert.ToInt32 strHdr.SecSize,
                                 Convert.ToInt32 strHdr.SecOffset)
  let sNum = symSec.SecSize / (if cls = WordSize.Bit32 then 16UL else 24UL)
  Convert.ToInt32 symSec.SecOffset |> sParse 0UL sNum strTab acc

let computeRangeSet map =
  let folder map = function
    | [| (sAddr, chunk); (eAddr, _) |] ->
      ARMap.add (AddrRange (sAddr, eAddr)) chunk map
    | _ -> failwith "Fatal error"
  Map.toSeq map
  |> Seq.filter (fun (addr, _) -> addr <> 0UL)
  |> Seq.windowed 2
  |> Seq.fold folder ARMap.empty

let genChunkMapBySTType chunk sym map map2 =
  match sym.SymType with
  | STTSection -> Map.add sym.Addr { chunk with SecELFSymbol = Some sym } map, map2
  | STTNoType -> Map.add sym.Addr { chunk with MappingELFSymbol = Some sym } map,
                 Map.add sym.Addr sym map2
  | STTFunc -> Map.add sym.Addr { chunk with FuncELFSymbol = Some sym } map, map2
  | _ -> Map.add sym.Addr chunk map, map2

let insertAddrChunkMap (map, map2) sym =
  let emptyChunk = { SecELFSymbol = None; FuncELFSymbol = None; MappingELFSymbol = None }
  match Map.tryFind sym.Addr map with
  | Some c -> genChunkMapBySTType c sym map map2
  | None -> genChunkMapBySTType emptyChunk sym map map2

let getChunks (symTbl: ELFSymbol []) (dynSym: ELFSymbol []) =
  let targetMap = if symTbl.Length = 0 then dynSym else symTbl
  let chunkMap, mappingSymbs =
    Array.fold insertAddrChunkMap (Map.empty, Map.empty) targetMap
  struct (computeRangeSet chunkMap, computeRangeSet mappingSymbs)

let pltFirstSkipBytes = function
| Arch.IntelX86
| Arch.IntelX64 -> 0x10UL
| Arch.ARMv7 -> 0x14UL
| Arch.AARCH64 -> 0x20UL
| _ -> failwith "Implement"

let isThumbPltELFSymbol sAddr (plt: ELFSection) (reader: BinReader) =
 let offset = Convert.ToInt32 (sAddr - plt.SecAddr + plt.SecOffset)
 reader.PeekBytes (4, offset) = pltThumbStubBytes

let findPltSize sAddr plt reader = function
  | Arch.IntelX86
  | Arch.IntelX64 -> 0x10UL
  | Arch.ARMv7 ->
    if isThumbPltELFSymbol sAddr plt reader then 0x10UL else 0x0CUL
  | Arch.AARCH64 -> 0x10UL
  | _ -> failwith "Implement"

let inline tryFindFuncSymb elf addr =
  if addr >= elf.SymInfo.PLTStart && addr < elf.SymInfo.PLTEnd then
    ARMap.tryFindByAddr addr elf.SymInfo.PLT
    >>= (fun s -> Some s.SymName)
  else
    ARMap.tryFindByAddr addr elf.SymInfo.SymChunks
    >>= (fun c -> c.FuncELFSymbol)
    >>= (fun s -> if s.Addr = addr then Some s.SymName else None)

let tryFindELFSymbolChunkRange elf addr =
  match ARMap.tryFindKey (addr + 1UL) elf.SymInfo.SymChunks with
  | Some range when range.Min = addr + 1UL -> Some range
  | _ -> ARMap.tryFindKey addr elf.SymInfo.SymChunks

let parsePLTELFSymbols arch sections (reloc: RelocInfo) reader =
  let plt = Map.find secPLT sections.SecByName
  let pltStartAddr = plt.SecAddr + pltFirstSkipBytes arch
  let pltEndAddr = plt.SecAddr + plt.SecSize
  let folder (map, sAddr) _ (rel: Relocation) =
    match rel.RelSecName with
    | ".rel.plt" | ".rela.plt" ->
      let nextStartAddr = sAddr + findPltSize sAddr plt reader arch
      let addrRange = AddrRange (sAddr, nextStartAddr)
      ARMap.add addrRange rel.RelELFSymbol map, nextStartAddr
    | _ -> map, sAddr
  struct (
    Map.fold folder (ARMap.empty, pltStartAddr) reloc.RelocByAddr |> fst,
    pltStartAddr,
    pltEndAddr
  )

let hasPLT secs = Map.containsKey secPLT secs.SecByName

let rec isValid addr = function
  | seg :: tl ->
    let vAddr = seg.PHAddr
    if addr >= vAddr && addr < vAddr + seg.PHFileSize then true
    else isValid addr tl
  | [] -> false

let rec translateAddr addr = function
  | seg :: tl ->
    let vAddr = seg.PHAddr
    if addr >= vAddr && addr < vAddr + seg.PHFileSize then
      Convert.ToInt32 (addr - vAddr + seg.PHOffset)
    else translateAddr addr tl
  | [] -> raise InvalidAddrReadException

let parseELFSymbolsFromSecs eHdr secs reader =
  let getSymSec typ = Map.tryFind typ secs.SecByType
  let getSym sec = Option.fold (parseELFSymbols eHdr.Class secs reader) [] sec
  let symTblByNum = getSymSec SHTSymTab |> getSym |> Array.ofList
  let dynSymTblByNum = getSymSec SHTDynSym |> getSym |> Array.ofList
  let struct (symChunks, mappingSymbs) = getChunks symTblByNum dynSymTblByNum
  let reloc = parseRelocation eHdr secs dynSymTblByNum reader
  let struct (plt, pltStart, pltEnd) =
    if hasPLT secs then parsePLTELFSymbols eHdr.MachineType secs reloc reader
    else struct (ARMap.empty, 0UL, 0UL)
  {
    DynSymArr = dynSymTblByNum
    StaticSymArr = symTblByNum
    SymChunks = symChunks
    MappingELFSymbols = mappingSymbs
    RelocInfo = reloc
    PLT = plt
    PLTStart = pltStart
    PLTEnd = pltEnd
  }

let parseELF offset reader =
  let eHdr = parseELFHeader reader offset
  let secs = parseSectionsFromEHdr eHdr reader
  let segs = parseProgHeaders eHdr reader
  let loadableSegs = segs |> List.filter (fun seg -> seg.PHType = PHTLoad)
  let loadableSecNums = computeLoadableSecNums secs loadableSegs
  let symInfo = parseELFSymbolsFromSecs eHdr secs reader
  {
    ELFHdr = eHdr
    Segments = segs
    LoadableSegments = loadableSegs
    LoadableSecNums = loadableSecNums
    Sections = secs
    SymInfo = symInfo
  }

let elfSymbolToSymbol target (symb: ELFSymbol) =
  {
    Address = symb.Addr
    Name = symb.SymName
    Kind = elfTypeToSymbKind symb.Ndx symb.SymType
    Target = target
    LibraryName = elfVersionToLibName symb.VerInfo
  }

let getAllStaticSymbols elf =
  elf.SymInfo.StaticSymArr
  |> Array.map (elfSymbolToSymbol TargetKind.StaticSymbol)

let getAllDynamicSymbols elf =
  elf.SymInfo.DynSymArr
  |> Array.map (elfSymbolToSymbol TargetKind.DynamicSymbol)

let secFlagToSectionKind flag entrySize =
  if flag &&& SectionFlag.SHFExecInstr = SectionFlag.SHFExecInstr then
    if entrySize > 0UL then SectionKind.LinkageTableSection
    else SectionKind.ExecutableSection
  elif flag &&& SectionFlag.SHFWrite = SectionFlag.SHFWrite then
    SectionKind.WritableSection
  else
    SectionKind.ExtraSection

let elfSectionToSection (sec: ELFSection) =
  {
    Address = sec.SecAddr
    Kind = secFlagToSectionKind sec.SecFlags sec.SecEntrySize
    Size = sec.SecSize
    Name = sec.SecName
  }

let getAllSections elf =
  elf.Sections.SecByNum
  |> Array.map (elfSectionToSection)
  |> Array.toSeq

let getSectionsByAddr elf addr =
  match ARMap.tryFindByAddr addr elf.Sections.SecByAddr with
  | Some s -> Seq.singleton (elfSectionToSection s)
  | None -> Seq.empty

let getSectionsByName elf name =
  match Map.tryFind name elf.Sections.SecByName with
  | Some s -> Seq.singleton (elfSectionToSection s)
  | None -> Seq.empty

let progHdrToSegment phdr =
  {
    Address = phdr.PHAddr
    Size = phdr.PHFileSize
    Permission = phdr.PHFlags |> LanguagePrimitives.EnumOfValue
  }

let getAllSegments elf =
  elf.LoadableSegments
  |> List.map progHdrToSegment
  |> List.toSeq

let getLinkageTableEntries elf =
  let create pltAddr (symb: ELFSymbol) =
    {
      FuncName = symb.SymName
      LibraryName = elfVersionToLibName symb.VerInfo
      TrampolineAddress = pltAddr
      TableAddress = symb.Addr
    }
  elf.SymInfo.PLT
  |> ARMap.fold (fun acc addrRange s -> create addrRange.Min s :: acc) []
  |> List.sortBy (fun entry -> entry.TrampolineAddress)
  |> List.toSeq

let getRelocSymbols elf =
  elf.SymInfo.RelocInfo.RelocByName
  |> Map.toSeq
  |> Seq.map (fun (_, i) -> { i.RelELFSymbol with Addr = i.RelOffset }
                            |> elfSymbolToSymbol TargetKind.DynamicSymbol)

let initELF bytes =
  let reader = BinReader.Init (bytes, Endian.Little)
  if isELFHeader reader startOffset then ()
  else raise FileFormatMismatchException
  readEndianness reader startOffset
  |> BinReader.RenewReader reader
  |> parseELF startOffset

let getTextSectionStartAddr elf =
  (Map.find secTEXT elf.Sections.SecByName).SecAddr

// vim: set tw=80 sts=2 sw=2:
