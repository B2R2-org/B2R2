(*
    B2R2 - the Next-Generation Reversing Platform

    Author: DongYeop Oh <oh51dy@kaist.ac.kr>

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

module internal B2R2.BinFile.Mach

open System
open B2R2
open B2R2.Monads.Maybe
open B2R2.BinFile.FileHelper

let secMachHeader = "__mach_header"
let secLoadCmds = "__load_commands"
let secTEXT = "__text"
let secSTUBS = "__stubs"
let secSYMBOLSTUB = "__symbol_stub"
let secSTUBHELPER = "__stub_helper"
let secUNWINDINFO = "__unwind_info"

let getStubs wordSize secs =
    if wordSize = WordSize.Bit64 then Map.tryFind secSTUBS secs
    else Map.tryFind secSYMBOLSTUB secs

let secStrings = [
    secTEXT
    secSYMBOLSTUB
    secSTUBS
    secSTUBHELPER
    secUNWINDINFO
]

let indirectSymbolLocal = 0x80000000u
let indirectSymbolABS = 0x40000000u

/// Symbol type field mask bits.
let n_type = 0x0euy
/// if any of these bits set, a symbolic debugging entry.
let n_stab = 0xe0uy
/// private external symbol bit.
let n_pext = 0x10uy
///  external symbol bit, set for external symbols.
let n_ext = 0x01uy
/// Defined Symbol type field N_SECT for MachSection number.
let n_sect = 0x0euy

/// 256 section types.
let section_Type = 0x000000ffu
/// 24 section attributes.
let section_attributes = 0xffffff00u

type MachHeaderMagic =
    | MHMagic
    | MHCigam
    | MHMagic64
    | MHCigam64

type CPUType =
    | CPUTypeAny
    | CPUTypeVAX
    | CPUTypeROMP
    | CPUTypeNS32032
    | CPUTypeNS32332
    | CPUTypeMC680x0
    | CPUTypeI386
    | CPUTypeX64
    | CPUTypeMIPS
    | CPUTypeNS32532
    | CPUTypeHPPA
    | CPUTypeARM
    | CPUTypeMC88000
    | CPUTypeSPARC
    | CPUTypeI860
    | CPUTypeI860LITTLE
    | CPUTypeRS6000
    | CPUTypePOWERPC
    | CPUTypeABI64
    | CPUTypePOWERPC64
    | CPUTypeVEO
    | CPUTypeARM64

type FileType =
    | MHFTObject
    | MHFTExecute
    | MHFTFvmlib
    | MHFTCore
    | MHFTPreload
    | MHFTDylib
    | MHFTDylinker
    | MHFTDybundle
    | MHFTDylibStub
    | MHFTDsym
    | MHFTKextBundle

type MachHeader = {
        Magic       : MachHeaderMagic
        Class       : WordSize
        CPUType     : CPUType
        CPUSubType  : int
        FileType    : FileType
        CmdsNum     : uint32
        CmdsSize    : uint32
        Flags       : uint32
}

type LoadCmdType =
    | LCSegment
    | LCSymTab
    | LCSymSeg
    | LCThread
    | LCUnixTherad
    | LCLoadFVMLib
    | LCIDFVMLib
    | LCIDInfo
    | LCFVMFile
    | LCPrepage
    | LCDySymTab
    | LCLoadDyLib
    | LCIDDyLib
    | LCLoadDyLink
    | LCIDDyLink
    | LCPreboundDyLib
    | LCRoutines
    | LCSubFramework
    | LCSubUmbrella
    | LCSubClient
    | LCSubLib
    | LCTwoLevelHints
    | LCPrebindCksum
    | LCLoadWeakDyLib
    | LCSegment64
    | LCRoutines64
    | LCUUID
    | LCRunPath
    | LCCodeSign
    | LCSegSplitInfo
    | LCReExportDyLib
    | LCLazyLoadDyLib
    | LCEncSegInfo
    | LCDyLDInfo
    | LCDyLDInfoOnly
    | LCLoadUpwordDyLib
    | LCVerMinMacOSX
    | LCVerMinIphoneOS
    | LCFunStarts
    | LCDyLDEnvir
    | LCMain
    | LCDataInCode
    | LCSourceVer
    | LCDyLibCodeSigDRS
    | LCEncInfo64
    | LCLinkOpt
    | LCLinkOptimizeHint
    | LCVerMinWatchOS
    | LCUnknown

type SecFlag =
    /// Regular section.
    | S_REGULAR                             = 0x0
    /// Zero fill on demand section.
    | S_ZEROFILL                            = 0x1
    /// Section with only literal C strings.
    | S_CSTRING_LITERALS                    = 0x2
    /// Section with only 4 byte literals.
    | S_4BYTE_LITERALS                      = 0x3
    /// Section with only 8 byte literals.
    | S_8BYTE_LITERALS                      = 0x4
    /// section with only pointers to literals.
    | S_LITERAL_POINTERS                    = 0x5
    /// Section with only non-lazy symbol pointers .
    | S_NON_LAZY_SYMBOL_POINTERS            = 0x6
    /// Section with only lazy symbol pointers.
    | S_LAZY_SYMBOL_POINTERS                = 0x7
    /// Section with only symbol stubs, byte size of stub in the reserved2 field.
    | S_SYMBOL_STUBS                        = 0x8
    /// Section with only function pointers for initialization.
    | S_MOD_INIT_FUNC_POINTERS              = 0x9
    /// Section with only function pointers for termination.
    | S_MOD_TERM_FUNC_POINTERS              = 0xa
    /// Section contains symbols that are to be coalesced.
    | S_COALESCED                           = 0xb
    /// Zero fill on demand section (that can be larger than 4 gigabytes).
    | S_GB_ZEROFILL                         = 0xc
    /// Section with only pairs of function pointers for interposing.
    | S_INTERPOSING                         = 0xd
    /// Section with only 16 byte literals.
    | S_16BYTE_LITERALS                     = 0xe
    /// Section contains DTrace Object Format.
    | S_DTRACE_DOF                          = 0xf
    /// Section with only lazy symbol pointers to lazy loaded dylibs.
    | S_LAZY_DYLIB_SYMBOL_POINTERS          = 0x10
    /// Template of initial values for TLVs.
    | S_THREAD_LOCAL_REGULAR                = 0x11
    /// Template of initial values for TLVs.
    | S_THREAD_LOCAL_ZEROFILL               = 0x12
    /// TLV descriptors.
    | S_THREAD_LOCAL_VARIABLES              = 0x13
    /// Pointers to TLV descriptors.
    | S_THREAD_LOCAL_VARIABLE_POINTERS      = 0x14
    /// Functions to call to initialize TLV values .
    | S_THREAD_LOCAL_INIT_FUNCTION_POINTERS = 0x15

type NType =
    /// undefined, n_sect == NO_SECT.
    | N_UNDF = 0x0
    /// absolute, n_sect == NO_SECT.
    | N_ABS = 0x2
    /// defined in section number n_sect.
    | N_SECT = 0xe
    /// prebound undefined (defined in a dylib).
    | N_PBUD = 0xc
    /// indirect.
    | N_INDR = 0xa

/// Debugg symbols type.
type STABS =
    /// global symbol: name,,NO_SECT,type,0.
    | N_GSYM    = 0x20
    /// procedure name (f77 kludge): name,,NO_SECT,0,0.
    | N_FNAME   = 0x22
    /// procedure: name,,n_sect,linenumber,address.
    | N_FUN     = 0x24
    /// static symbol: name,,n_sect,type,address.
    | N_STSYM   = 0x26
    /// .lcomm symbol: name,,n_sect,type,address.
    | N_LCSYM   = 0x28
    /// begin nsect sym: 0,,n_sect,0,address.
    | N_BNSYM   = 0x2e
    /// AST file path: name,,NO_SECT,0,0.
    | N_AST     = 0x32
    /// emitted with gcc2_compiled and in gcc source.
    | N_OPT     = 0x3c
    /// register sym: name,,NO_SECT,type,register.
    | N_RSYM    = 0x40
    /// src line: 0,,n_sect,linenumber,address.
    | N_SLINE   = 0x44
    /// end nsect sym: 0,,n_sect,0,address.
    | N_ENSYM   = 0x4e
    /// structure elt: name,,NO_SECT,type,struct_offset.
    | N_SSYM    = 0x60
    /// source file name: name,,n_sect,0,address.
    | N_SO      = 0x64
    /// object file name: name,,0,0,st_mtime.
    | N_OSO     = 0x66
    /// local sym: name,,NO_SECT,type,offset.
    | N_LSYM    = 0x80
    /// include file beginning: name,,NO_SECT,0,sum.
    | N_BINCL   = 0x82
    /// #included file name: name,,n_sect,0,address.
    | N_SOL     = 0x84
    /// compiler parameters: name,,NO_SECT,0,0.
    | N_PARAMS  = 0x86
    /// compiler version: name,,NO_SECT,0,0.
    | N_VERSION = 0x88
    /// compiler -O level: name,,NO_SECT,0,0.
    | N_OLEVEL  = 0x8a
    /// parameter: name,,NO_SECT,type,offset.
    | N_PSYM    = 0xa0
    /// include file end: name,,NO_SECT,0,0.
    | N_EINCL   = 0xa2
    /// alternate entry: name,,n_sect,linenumber,address.
    | N_ENTRY   = 0xa4
    /// left bracket: 0,,NO_SECT,nesting level,address.
    | N_LBRAC   = 0xc0
    /// deleted include file: name,,NO_SECT,0,sum.
    | N_EXCL    = 0xc2
    /// right bracket: 0,,NO_SECT,nesting level,address.
    | N_RBRAC   = 0xe0
    /// begin common: name,,NO_SECT,0,0.
    | N_BCOMM   = 0xe2
    /// end common: name,,n_sect,0,0.
    | N_ECOMM   = 0xe4
    /// end common (local name): 0,,n_sect,0,address.
    | N_ECOML   = 0xe8
    /// second stab entry with length information.
    | N_LENG    = 0xfe
    /// global pascal symbol: name,,NO_SECT,subtype,line (for berkeley compiler).
    | N_PC      = 0x30

type LoadCommand = {
    Cmd     : LoadCmdType
    CmdSize : uint32
}

type SegCmd = {
    Cmd         : LoadCmdType
    CmdSize     : uint32
    CmdOff      : Addr
    SegName     : string
    VMAddr      : Addr
    VMSize      : uint64
    FileOff     : Addr
    FileSize    : uint64
    MaxVMProt   : int
    InitVMProt  : int
    NumOfSec    : uint32
    SegFlag     : uint32
}

type SymTabCmd = {
    Cmd         : LoadCmdType
    CmdSize     : uint32
    CmdOff      : Addr
    SymOff      : Addr
    NumOfSym    : uint32
    StrOff      : Addr
    StrSize     : int
}

type DySymTabCmd = {
    Cmd             : LoadCmdType
    CmdSize         : uint32
    CmdOff          : Addr
    IdxLocalSym     : uint32
    NumLocalSym     : uint32
    IdxExtSym       : uint32
    NumExtSym       : uint32
    IdxUndefSym     : uint32
    NumUndefSym     : uint32
    ContentTabOff   : Addr
    NumContentTab   : uint32
    ModTabOff       : Addr
    NumModTab       : uint32
    ExtRefSymOff    : Addr
    NumExtRefSym    : uint32
    IndirectSymOff  : Addr
    NumIndirectSym  : uint32
    ExtRelOff       : Addr
    NumExtRel       : uint32
    LocalRelOff     : Addr
    NumLocalRel     : uint32
}

type MainCmd = {
    Cmd             : LoadCmdType
    CmdSize         : uint32
    CmdOff          : Addr
    EntryOff        : Addr
    StackSize       : uint64
}

type DyLibCmd = {
    Cmd             : LoadCmdType
    CmdSize         : uint32
    CmdOff          : Addr
    DyLibName       : string
    Time            : uint32 (* library's build time stamp *)
    DyLibCurVer     : uint32 (* library's current version number *)
    DyLibCmpVer     : uint32 (* library's compatibility vers number *)
}

type Cmds =
    | Load of LoadCommand
    | Seg of SegCmd
    | Sym of SymTabCmd
    | DySym of DySymTabCmd
    | Main of MainCmd
    | DyLib of DyLibCmd

type MachSection = {
    SecName       : string
    SegName       : string
    SecAddr       : Addr
    SecSize       : uint64
    SecOffset     : uint32
    SecAlignment  : uint32
    SecRelOff     : uint32
    SecNumOfReloc : uint32
    SecFlags      : uint32
    SecReserved1  : uint32
    SecReserved2  : uint32
}

type SectionTbl = {
    SecByAddr  : ARMap<MachSection>
    SecByName  : Map<string, MachSection>
    SecByNum   : MachSection []
}

type MachSymbol = {
    SymName    : string
    SymType    : byte
    SecNum     : byte
    SymDesc    : int16
    VerInfo    : DyLibCmd option
    SymAddr    : uint64
}

type IndSymbol = {
    IndAddr    : Addr
    Symbol     : MachSymbol
    IndSecName : string
}

type SymbolTbl = {
    SymByAddr  : Map<Addr,MachSymbol list>
    SymByName  : Map<string, MachSymbol>
    SymByNum   : MachSymbol []
}

type IndSymTbl = {
    ISymByAddr  : Map<Addr,IndSymbol>
    ISymByName  : Map<string, IndSymbol>
    ISymByNum   : IndSymbol []
}

type SymInfo = {
    Sym                : SymbolTbl
    IndSym             : IndSymTbl
    StaticSymArr       : MachSymbol []
    DynamicSymArr      : MachSymbol []
    LinkageTableEntry  : Map<Addr, LinkageTableEntry>
    StabsStart         : Addr
    StabsEnd           : Addr
}

type Mach = {
    EntryPoint  : Addr
    MachHdr     : MachHeader
    Segment     : SegCmd list
    Sections    : SectionTbl
    SymInfo     : SymInfo
}

let readMagic (reader : BinReader) offset =
    match reader.PeekUInt32 offset with
    | 0xFEEDFACEu -> MHMagic
    | 0xCEFAEDFEu -> MHCigam
    | 0xFEEDFACFu -> MHMagic64
    | 0xCFFAEDFEu -> MHCigam64
    | t -> failwithf "invalid Mach Magic Number (%02x)" t

let isMachHeader (reader : BinReader) offset =
    try readMagic reader offset |> (fun _ -> true) with _ -> false

let readCPUType (reader: BinReader) offset =
    let cpuOffset = 4
    match offset + cpuOffset |> reader.PeekInt32 with
    | 0xFFFFFFFF -> CPUTypeAny
    | 0x00000001 -> CPUTypeVAX
    | 0x00000002 -> CPUTypeROMP
    | 0x00000004 -> CPUTypeNS32032
    | 0x00000005 -> CPUTypeNS32332
    | 0x00000006 -> CPUTypeMC680x0
    | 0x00000007 -> CPUTypeI386
    | 0x01000007 -> CPUTypeX64
    | 0x00000008 -> CPUTypeMIPS
    | 0x00000009 -> CPUTypeNS32532
    | 0x0000000B -> CPUTypeHPPA
    | 0x0000000C -> CPUTypeARM
    | 0x0000000D -> CPUTypeMC88000
    | 0x0000000E -> CPUTypeSPARC
    | 0x0000000F -> CPUTypeI860
    | 0x00000010 -> CPUTypeI860LITTLE
    | 0x00000011 -> CPUTypeRS6000
    | 0x00000012 -> CPUTypePOWERPC
    | 0x01000000 -> CPUTypeABI64
    | 0x01000012 -> CPUTypePOWERPC64
    | 0x000000FF -> CPUTypeVEO
    | 0x0100000C -> CPUTypeARM64
    | t -> failwithf "invalid Mach CPU type (%02x)" t

let readCPUSubType (reader: BinReader) offset =
    let cpuSubTypeOffset = 8
    offset + cpuSubTypeOffset |> reader.PeekInt32 |> (fun i -> i &&& 0x00ffffff)

/// FIXME
let getMIPSISA (reader: BinReader) offset =
    match readCPUSubType reader offset with
    | 0x0 | 0x1 | 0x2 | 0x3 | 0x4 -> Arch.MIPS32R2
    | t -> failwithf "invalid MIPS CPU subtype (%02x)" t

let readArch reader offset =
    match readCPUType reader offset with
    | CPUTypeI386 -> Arch.IntelX86
    | CPUTypeX64 -> Arch.IntelX64
    | CPUTypeARM -> Arch.ARMv7
    | CPUTypeARM64 -> Arch.AARCH64
    | CPUTypeMIPS -> getMIPSISA reader offset
    | _ -> Arch.UnknownISA

let readClass reader offset =
    match readMagic reader offset with
    | MHMagic | MHCigam -> WordSize.Bit32
    | MHMagic64 | MHCigam64 -> WordSize.Bit64

let readEndianness reader offset =
    match readMagic reader offset with
    | MHMagic | MHMagic64 -> Endian.Little
    | MHCigam | MHCigam64 -> Endian.Big

let readFileType (reader: BinReader) offset =
    let fileTypeOffset = 12
    match offset + fileTypeOffset |> reader.PeekUInt32 with
    | 0x1u -> MHFTObject
    | 0x2u -> MHFTExecute
    | 0x3u -> MHFTFvmlib
    | 0x4u -> MHFTCore
    | 0x5u -> MHFTPreload
    | 0x6u -> MHFTDylib
    | 0x7u -> MHFTDylinker
    | 0x8u -> MHFTDybundle
    | 0x9u -> MHFTDylibStub
    | 0xau -> MHFTDsym
    | 0xbu -> MHFTKextBundle
    | t -> failwithf "invalid Mach file type(%02x)" t

let readCmdsNum (reader: BinReader) offset =
    let cmdsNumOffset = 16
    offset + cmdsNumOffset |> reader.PeekUInt32

let readCmdsSize (reader: BinReader) offset =
    let cmdsSizeOffset = 20
    offset + cmdsSizeOffset |> reader.PeekUInt32

let readMachFlags (reader: BinReader) offset =
    let cmdsSizeOffset = 24
    offset + cmdsSizeOffset |> reader.PeekUInt32

let parseMachHeader reader offset =
    {
        Magic = readMagic reader offset
        Class = readClass reader offset
        CPUType = readCPUType reader offset
        CPUSubType = readCPUSubType reader offset
        FileType = readFileType reader offset
        CmdsNum = readCmdsNum reader offset
        CmdsSize = readCmdsSize reader offset
        Flags = readMachFlags reader offset
    }

let readSegName (reader: BinReader) offset =
    let segNameOffset = 8
    let name = String (reader.PeekChars (16, offset + segNameOffset))
    Array.get (name.Split('\000')) 0

let readSegVMAddr (reader: BinReader) cls offset =
    let segVMAddrOffset = 24
    offset + segVMAddrOffset |> peekUIntOfType reader cls

let readSegVMSize (reader: BinReader) cls offset =
    let segVMSizeOffset = if cls = WordSize.Bit32 then 28 else 32
    offset + segVMSizeOffset |> peekUIntOfType reader cls

let readSegFileOffset (reader: BinReader) cls offset =
    let offsetOfSegFileOffset = if cls = WordSize.Bit32 then 32 else 40
    offset + offsetOfSegFileOffset |> peekUIntOfType reader cls

let readSegFileSize (reader: BinReader) cls offset =
    let segFileSizeOffset = if cls = WordSize.Bit32 then 36 else 48
    offset + segFileSizeOffset |> peekUIntOfType reader cls

let readSegMaxVMProtection (reader: BinReader) cls offset =
    let segMaxVMProtectionOffset = if cls = WordSize.Bit32 then 40 else 56
    offset + segMaxVMProtectionOffset |> reader.PeekInt32

let readSegInitVMProtection (reader: BinReader) cls offset =
    let segInitVMProtectionOffset = if cls = WordSize.Bit32 then 44 else 60
    offset + segInitVMProtectionOffset |> reader.PeekInt32

let readNumOfSecInSeg (reader: BinReader) cls offset =
    let numOfSecInSegOffset = if cls = WordSize.Bit32 then 48 else 64
    offset + numOfSecInSegOffset |> reader.PeekUInt32

let readSegFlag (reader: BinReader) cls offset =
    let segFlagOffset = if cls = WordSize.Bit32 then 52 else 68
    offset + segFlagOffset |> reader.PeekUInt32

let parseSegCmd (reader: BinReader) cmd size cls offset =
    {
        Cmd = cmd
        CmdSize = size
        CmdOff = uint64 offset
        SegName = readSegName reader offset
        VMAddr = readSegVMAddr reader cls offset
        VMSize = readSegVMSize reader cls offset
        FileOff = readSegFileOffset reader cls offset
        FileSize = readSegFileSize reader cls offset
        MaxVMProt = readSegMaxVMProtection reader cls offset
        InitVMProt = readSegInitVMProtection reader cls offset
        NumOfSec = readNumOfSecInSeg reader cls offset
        SegFlag = readSegFlag reader cls offset
    }

let readSymOffset (reader: BinReader) offset =
    let offsetOfSymOffset = 8
    offset + offsetOfSymOffset |> reader.PeekUInt32 |> uint64

let readNumOfSym (reader: BinReader) offset =
    let numOfSymOffset = 12
    offset + numOfSymOffset |> reader.PeekUInt32

let readStrTblOffset (reader: BinReader) offset =
    let offsetOfStrTblOffset = 16
    offset + offsetOfStrTblOffset |> reader.PeekUInt32 |> uint64

let readStrSize (reader: BinReader) offset =
    let strSizeOffset = 20
    offset + strSizeOffset |> reader.PeekInt32

let parseSymCmd (reader: BinReader) cmd size offset =
    {
        Cmd = cmd
        CmdSize = size
        CmdOff = uint64 offset
        SymOff = readSymOffset reader offset
        NumOfSym = readNumOfSym reader offset
        StrOff = readStrTblOffset reader offset
        StrSize = readStrSize reader offset
    }

let readIdxLocalSym (reader: BinReader) offset =
    let idxLocalSymOffset = 8
    offset + idxLocalSymOffset |> reader.PeekUInt32

let readNumLocalSym (reader: BinReader) offset =
    let numLocalSymOffset = 12
    offset + numLocalSymOffset |> reader.PeekUInt32

let readIdxExtSym (reader: BinReader) offset =
    let idxExtSymOffset = 16
    offset + idxExtSymOffset |> reader.PeekUInt32

let readNumExtSym (reader: BinReader) offset =
    let numExtSymOffset = 20
    offset + numExtSymOffset |> reader.PeekUInt32

let readIdxUndefSym (reader: BinReader) offset =
    let idxUndefSymOffset = 24
    offset + idxUndefSymOffset |> reader.PeekUInt32

let readNumUndefSym (reader: BinReader) offset =
    let numUndefSymOffset = 28
    offset + numUndefSymOffset |> reader.PeekUInt32

let readContentTabOff (reader: BinReader) offset =
    let contentTabOffOffset = 32
    offset + contentTabOffOffset |> reader.PeekUInt32 |> uint64

let readNumContentTab (reader: BinReader) offset =
    let numContentTabOffset = 36
    offset + numContentTabOffset |> reader.PeekUInt32

let readModTabOff (reader: BinReader) offset =
    let offsetOfModTabOffset = 40
    offset + offsetOfModTabOffset |> reader.PeekUInt32 |> uint64

let readNumModTab (reader: BinReader) offset =
    let numModTabOffset = 44
    offset + numModTabOffset |> reader.PeekUInt32

let readExtRefSymOff (reader: BinReader) offset =
    let offsetOfExtRefSymOffset = 48
    offset + offsetOfExtRefSymOffset |> reader.PeekUInt32 |> uint64

let readNumExtRefSym (reader: BinReader) offset =
    let numExtRefSymOffset = 52
    offset + numExtRefSymOffset |> reader.PeekUInt32

let readIndirectSymOff (reader: BinReader) offset =
    let offsetOfIndirectSymOffset = 56
    offset + offsetOfIndirectSymOffset |> reader.PeekUInt32 |> uint64

let readNumIndirectSym (reader: BinReader) offset =
    let numIndirectSymOffset = 60
    offset + numIndirectSymOffset |> reader.PeekUInt32

let readExtRelOff (reader: BinReader) offset =
    let offsetOfExtRelOffset = 64
    offset + offsetOfExtRelOffset |> reader.PeekUInt32 |> uint64

let readNumExtRel (reader: BinReader) offset =
    let numExtReOffset = 68
    offset + numExtReOffset |> reader.PeekUInt32

let readLocalRelOff (reader: BinReader) offset =
    let offsetOfLocalRelOffset = 72
    offset + offsetOfLocalRelOffset |> reader.PeekUInt32 |> uint64

let readNumLocalRel (reader: BinReader) offset =
    let numLocalRelOffset = 76
    offset + numLocalRelOffset |> reader.PeekUInt32

let parseDySymCmd (reader: BinReader) cmd size offset =
    {
        Cmd = cmd
        CmdSize = size
        CmdOff = uint64 offset
        IdxLocalSym = readIdxLocalSym reader offset
        NumLocalSym = readNumLocalSym reader offset
        IdxExtSym = readIdxExtSym reader offset
        NumExtSym = readNumExtSym reader offset
        IdxUndefSym = readIdxUndefSym reader offset
        NumUndefSym = readNumUndefSym reader offset
        ContentTabOff = readContentTabOff reader offset
        NumContentTab = readNumContentTab reader offset
        ModTabOff = readModTabOff reader offset
        NumModTab = readNumModTab reader offset
        ExtRefSymOff = readExtRefSymOff reader offset
        NumExtRefSym = readNumExtRefSym reader offset
        IndirectSymOff = readIndirectSymOff reader offset
        NumIndirectSym = readNumIndirectSym reader offset
        ExtRelOff = readExtRelOff reader offset
        NumExtRel = readNumExtRel reader offset
        LocalRelOff = readLocalRelOff reader offset
        NumLocalRel = readNumLocalRel reader offset
    }

let readEntryOffset (reader: BinReader) offset =
    let entryOffset = 8
    offset + entryOffset |> reader.PeekUInt64

let readStackSize (reader: BinReader) offset =
    let stackSizeOffset = 16
    offset + stackSizeOffset |> reader.PeekUInt64

let parseMainCmd (reader: BinReader) cmd size offset =
    {
        Cmd = cmd
        CmdSize = size
        CmdOff = uint64 offset
        EntryOff = readEntryOffset reader offset
        StackSize = readStackSize reader offset
    }

let readDyLibName (reader: BinReader) size offset =
    let dyLibNameOffset = 8
    let offset' = offset + dyLibNameOffset
    let strLen = size - reader.PeekUInt32 offset' |> Convert.ToInt32
    let strOffset = offset' + 16
    let name = String (reader.PeekChars (strLen, strOffset))
    Array.get (name.Split('\000')) 0

let readLibBuildTime (reader: BinReader) offset =
    let LibBuildTimeOffset = 12
    offset + LibBuildTimeOffset |> reader.PeekUInt32

let readDyLibCurrentVer (reader: BinReader) offset =
    let dyLibCurrentVerOffset = 16
    offset + dyLibCurrentVerOffset |> reader.PeekUInt32

let readDyLibCompatibilityVer (reader: BinReader) offset =
    let dyLibCompatibilityVerOffset = 20
    offset + dyLibCompatibilityVerOffset|> reader.PeekUInt32

let deletePath (libName: string) =
    let word = libName.Split ('/')
    Array.get word (word.Length - 1)

let parseDyLibCmd (reader: BinReader) cmd size offset =
    {
        Cmd = cmd
        CmdSize = size
        CmdOff = uint64 offset
        DyLibName = readDyLibName reader size offset |> deletePath
        Time = readLibBuildTime reader offset
        DyLibCurVer = readDyLibCurrentVer reader offset
        DyLibCmpVer = readDyLibCompatibilityVer reader offset
    }

let readLoadCmdType (reader: BinReader) offset =
    match reader.PeekUInt32 offset with
    | 0x01u -> LCSegment
    | 0x02u -> LCSymTab
    | 0x03u -> LCSymSeg
    | 0x04u -> LCThread
    | 0x05u -> LCUnixTherad
    | 0x06u -> LCLoadFVMLib
    | 0x07u -> LCIDFVMLib
    | 0x08u -> LCIDInfo
    | 0x09u -> LCFVMFile
    | 0x0Au -> LCPrepage
    | 0x0Bu -> LCDySymTab
    | 0x0Cu -> LCLoadDyLib
    | 0x0Du -> LCIDDyLib
    | 0x0Eu -> LCLoadDyLink
    | 0x0Fu -> LCIDDyLink
    | 0x10u -> LCPreboundDyLib
    | 0x11u -> LCRoutines
    | 0x12u -> LCSubFramework
    | 0x13u -> LCSubUmbrella
    | 0x14u -> LCSubClient
    | 0x15u -> LCSubLib
    | 0x16u -> LCTwoLevelHints
    | 0x17u -> LCPrebindCksum
    | 0x80000018u -> LCLoadWeakDyLib
    | 0x19u -> LCSegment64
    | 0x1Au -> LCRoutines64
    | 0x1Bu -> LCUUID
    | 0x8000001Cu -> LCRunPath
    | 0x1Du -> LCCodeSign
    | 0x1Eu -> LCSegSplitInfo
    | 0x1Fu -> LCReExportDyLib
    | 0x20u -> LCLazyLoadDyLib
    | 0x21u -> LCEncSegInfo
    | 0x22u -> LCDyLDInfo
    | 0x80000022u -> LCDyLDInfoOnly
    | 0x80000023u -> LCLoadUpwordDyLib
    | 0x24u -> LCVerMinMacOSX
    | 0x25u -> LCVerMinIphoneOS
    | 0x26u -> LCFunStarts
    | 0x27u -> LCDyLDEnvir
    | 0x80000028u -> LCMain
    | 0x29u -> LCDataInCode
    | 0x2Au -> LCSourceVer
    | 0x2Bu -> LCDyLibCodeSigDRS
    | 0x2Cu -> LCEncInfo64
    | 0x2Du -> LCLinkOpt
    | 0x2Eu -> LCLinkOptimizeHint
    | 0x30u -> LCVerMinWatchOS
    | _ -> LCUnknown

let readCmdSize (reader: BinReader) offset =
    let cmdSizeOffset = 4
    offset + cmdSizeOffset |> reader.PeekUInt32

let parseCmd (reader: BinReader) cls offset =
    let cmdType = readLoadCmdType reader offset
    let cmdSize = readCmdSize reader offset
    let command =
        match cmdType with
        | LCSegment
        | LCSegment64 -> Seg (parseSegCmd reader cmdType cmdSize cls offset)
        | LCSymTab -> Sym (parseSymCmd reader cmdType cmdSize offset)
        | LCDySymTab -> DySym (parseDySymCmd reader cmdType cmdSize offset)
        | LCMain -> Main (parseMainCmd reader cmdType cmdSize offset)
        | LCLoadDyLib -> DyLib (parseDyLibCmd reader cmdType cmdSize offset)
        | _ -> Load { Cmd = cmdType; CmdSize = cmdSize }
    struct (command, cmdSize)

let parseCmds reader offset machHdr =
    let rec parse cNum acc offset =
        if cNum = 0u then List.rev acc
        else 
            let struct (cmd, cmdSize) = parseCmd reader machHdr.Class offset
            let nextOffset = offset + Convert.ToInt32 cmdSize
            parse (cNum - 1u) (cmd :: acc) nextOffset
    let cmdOffset = if machHdr.Class = WordSize.Bit32 then 28 else 32
    offset + cmdOffset |> parse machHdr.CmdsNum []

let parseSection (reader: BinReader) cls pos =
    let struct (secName, nextPos) = reader.ReadChars (16, pos)
    let struct (segName, nextPos) = reader.ReadChars (16, nextPos)
    let struct (secAddr, nextPos) = readUIntOfType reader cls nextPos
    let struct (secSize, nextPos) = readUIntOfType reader cls nextPos
    let struct (secOffset, nextPos) = reader.ReadUInt32 nextPos
    let struct (secAlignment, nextPos) = reader.ReadUInt32 nextPos
    let struct (secRelOff, nextPos) = reader.ReadUInt32 nextPos
    let struct (secNumOfReloc, nextPos) = reader.ReadUInt32 nextPos
    let struct (secFlags, nextPos) = reader.ReadUInt32 nextPos
    let struct (secReserved1, nextPos) = reader.ReadUInt32  nextPos
    let struct (secReserved2, nextPos) = reader.ReadUInt32  nextPos
    struct (
        {
            SecName = Array.get ((String secName).Split('\000')) 0
            SegName = Array.get ((String segName).Split('\000')) 0
            SecAddr = secAddr
            SecSize = secSize
            SecOffset = secOffset
            SecAlignment = secAlignment
            SecRelOff = secRelOff
            SecNumOfReloc = secNumOfReloc
            SecFlags = secFlags
            SecReserved1 = secReserved1
            SecReserved2 = secReserved2
        }, if cls = WordSize.Bit64 then nextPos + 4 else nextPos
    )

let parseLibs cmds =
    let getLib acc = function
        | DyLib s -> s :: acc
        | _ -> acc
    List.fold getLib [] cmds |> List.rev

let parseSegment cmds =
    let getSeg acc = function
        | Seg s -> s :: acc
        | _ -> acc
    List.fold getSeg [] cmds |> List.rev

let genSecs {SecByAddr = addrMap; SecByName = nameMap; SecByNum = secArr} sec =
    let addrMap =
        ARMap.addRange sec.SecAddr (sec.SecAddr + sec.SecSize) sec addrMap
    let nameMap = Map.add sec.SecName sec nameMap
    let lst = sec :: Array.toList secArr
    {
        SecByAddr = addrMap
        SecByName = nameMap
        SecByNum = Array.ofList lst
    }

let genMacHdrSec (textSeg: SegCmd) cmdOff secs =
    {
        SecName = secMachHeader
        SegName = "__TEXT"
        SecAddr = textSeg.VMAddr
        SecSize = uint64 cmdOff
        SecOffset = 0u
        SecAlignment = 0u
        SecRelOff = 0u
        SecNumOfReloc = 0u
        SecFlags = 0u
        SecReserved1 = 0u
        SecReserved2 = 0u
    } |> genSecs secs

let genCmdHdrSec (textSeg: SegCmd) cmdOff (textSec: MachSection) secs =
    let secAddr = textSeg.VMAddr + uint64 cmdOff
    {
        SecName = secLoadCmds
        SegName = "__TEXT"
        SecAddr = secAddr
        SecSize = textSec.SecAddr - secAddr
        SecOffset = uint32 cmdOff
        SecAlignment = 0u
        SecRelOff = 0u
        SecNumOfReloc = 0u
        SecFlags = 0u
        SecReserved1 = 0u
        SecReserved2 = 0u
    } |> genSecs secs

/// N.B. Mach-O file format does not call these regions as a section, but they
/// are indeed loaded at runtime in the memory, within a segment. Therefore, we
/// consider them as a section. These parts correspond to the actual Mach-O file
/// header.
let parseHeaderSection mHdr (segs: SegCmd list) (secs: SectionTbl) =
    let cmdOff = if mHdr.Class = WordSize.Bit32 then 28 else 32
    let textSeg = List.tryFind (fun (s: SegCmd) -> s.SegName = "__TEXT") segs
    let textSec = Map.tryFind secTEXT secs.SecByName
    match textSeg, textSec with
    | Some seg, Some sec ->
        genCmdHdrSec seg cmdOff sec secs
        |> genMacHdrSec seg cmdOff
    | _ -> secs

let parseSections cls cmds reader =
    let acc = ARMap.empty, Map.empty, []
    let segHdrSize cls = if cls = WordSize.Bit64 then 72UL else 56UL
    let genSections (addrMap, nameMap, lst) sec =
        ARMap.addRange sec.SecAddr (sec.SecAddr + sec.SecSize) sec addrMap,
        Map.add sec.SecName sec nameMap,
        sec :: lst
    let rec loop count acc pos =
        if count = 0u then acc
        else 
            let struct (sec, nextPos) = parseSection reader cls pos
            loop (count - 1u) (genSections acc sec) nextPos

    let secParse map = function
        | Seg seg -> 
            let pos = Convert.ToInt32 (seg.CmdOff + segHdrSize cls)
            loop seg.NumOfSec map pos
        | _ -> map
    let secByAddr, secByName, secByNum =  List.fold secParse acc cmds
    {
        SecByAddr = secByAddr
        SecByName = secByName
        SecByNum = List.rev secByNum |> Array.ofList
    }

let inline isSecSymb flags = flags &&& n_type = n_sect
let inline isSymbTab flags = flags &&& n_stab <> 0x0uy
let inline isExternal flags = flags &&& n_ext <> 0x0uy

let parseSymbol (reader: BinReader) strBytes cls (libs: DyLibCmd list) pos =
    let symDesc = reader.PeekInt16 (pos + 6)
    let symVerInfo =
        let idx = symDesc >>> 8 |> int
        if idx <= 0 || idx > libs.Length then None
        else Some libs.[idx - 1]
    struct(
        {
            SymName = reader.PeekInt32 (pos) |> ByteArray.extractCString strBytes
            SymType = reader.PeekByte (pos + 4)
            SecNum = reader.PeekByte (pos + 5)
            SymDesc = reader.PeekInt16 (pos + 6)
            VerInfo = symVerInfo
            SymAddr = peekUIntOfType reader cls (pos + 8)
        }, pos + 8 + (WordSize.toByteWidth cls |> int)
    )

let parseSymbolInfo reader acc cls strBytes libs cmd =
    let genSymbolTbl (addrMap, nameMap, lst) sym =
        let addrMap =
            match Map.tryFind sym.SymAddr addrMap with
            | Some lst -> Map.add sym.SymAddr (sym :: lst) addrMap
            | None -> Map.add sym.SymAddr [sym] addrMap
        addrMap, Map.add sym.SymName sym nameMap, sym :: lst
    let getSymbol sym =
        let rec parse count acc pos =
            if count = 0u then acc
            else 
                let struct (sym, nextPos) = parseSymbol reader strBytes cls libs pos
                parse (count - 1u) (genSymbolTbl acc sym) nextPos
        Convert.ToInt32 sym.SymOff |> parse sym.NumOfSym acc
    match cmd with
    | Sym symCmd -> getSymbol symCmd
    | _ -> acc

let rec parseStrBytes cmds (reader: BinReader) =
    match cmds with
    | [] -> [||]
    | Sym s :: _ -> reader.PeekBytes (s.StrSize, Convert.ToInt32 s.StrOff)
    | _ :: tl -> parseStrBytes tl reader

let getIndirecSymInfo cmds (reader: BinReader) =
    let indirecSymInfo acc = function
        | DySym dySym ->
            let rec loop count acc pos =
                if count = 0u then acc
                else loop (count - 1u) (reader.PeekUInt32 pos :: acc) (pos + 4)
            loop dySym.NumIndirectSym acc (Convert.ToInt32 dySym.IndirectSymOff)
        | _ -> acc
    List.fold indirecSymInfo [] cmds |> List.rev

let checkIndirectSymbolData data =
      data = indirectSymbolLocal || data = indirectSymbolABS

let parseIndSym acc cnt stride (sInfo: uint32 list) sec (syms : MachSymbol []) =
        let (addrMap, nameMap, lst) = acc
        let data = sInfo.[cnt + sec.SecReserved1 |> Convert.ToInt32]
        let sym = 
            if checkIndirectSymbolData data then None
            else 
                let data = Convert.ToInt32 data
                if data < syms.Length then Some syms.[data] else None
        match sym with
        | Some s ->
            let iSym = { 
                IndAddr = sec.SecAddr + (uint64 cnt * uint64 stride)
                Symbol = s
                IndSecName = sec.SecName 
            }
            Map.add iSym.IndAddr iSym addrMap,
            Map.add iSym.Symbol.SymName iSym nameMap,
            iSym :: lst
        | None -> addrMap, nameMap, lst

let hasNonLazySymbolPtr flags = flags &&& 0x6u = 0x6u
let hasLazySymbolPtr flags = flags &&& 0x7u = 0x7u
let hasSymbolStubs flags = flags &&& 0x8u = 0x8u

let parseIndSymbolInfo acc indSymInfo cls symByNum sec =
    let parse stride =
        let count = uint32 <| sec.SecSize / uint64 stride
        let rec parse' acc sNum =
            if sNum = count then acc
            else 
                let acc = parseIndSym acc sNum stride indSymInfo sec symByNum
                parse' acc (sNum + 1ul)
        parse' acc 0ul
    if hasSymbolStubs sec.SecFlags then parse (Convert.ToInt32 sec.SecReserved2)
    elif hasNonLazySymbolPtr sec.SecFlags || hasLazySymbolPtr sec.SecFlags then
        parse (WordSize.toByteWidth cls)
    else acc

let classifySymbol symByNum =
    let folder (sSyms, dSyms) sym =
        (* If SecNum = 0, it means the symbol cannot be found in any section. *)
        if isSymbTab sym.SymType && sym.SecNum > 0uy then (sym :: sSyms, dSyms)
        elif isSecSymb sym.SymType && sym.SecNum > 0uy then (sym :: sSyms, dSyms)
        elif isExternal sym.SymType then (sSyms, sym :: dSyms)
        else (sSyms, dSyms)
    Array.fold folder ([], []) symByNum

let machVersionToLibName version =
    match version with
    | Some version -> version.DyLibName
    | None -> ""

let getLinkageTableEntry symByNum laSymByName =
    let create targetAddr (iSym: IndSymbol) =
        {
            FuncName = iSym.Symbol.SymName
            LibraryName = machVersionToLibName iSym.Symbol.VerInfo
            TrampolineAddress = iSym.IndAddr
            TableAddress = targetAddr
        }
    let folder map sym =
        if sym.IndSecName = secSYMBOLSTUB || sym.IndSecName = secSTUBS then
            match Map.tryFind sym.Symbol.SymName laSymByName with
            | Some s -> Map.add sym.IndAddr (create s.IndAddr sym) map
            | None -> map
        else map
    Array.fold folder Map.empty symByNum

let getLaSymPtrs syms =
    let folder acc s =
        if s.IndSecName = "__la_symbol_ptr"
            then Map.add s.Symbol.SymName s acc else acc
    Array.fold folder Map.empty syms

let genSym byAddr byName byNum =
    {
        SymByAddr = byAddr
        SymByName = byName
        SymByNum = byNum
    }

let genIndSym byAddr byName byNum =
    {
        ISymByAddr = byAddr
        ISymByName = byName
        ISymByNum = byNum
    }

let parseSymbols cls cmds secs libs reader =
    let acc = Map.empty, Map.empty, []
    let strBytes = parseStrBytes cmds reader
    let symParse acc cmd = parseSymbolInfo reader acc cls strBytes libs cmd
    let symByAddr, symByName, symByNum = List.fold symParse acc cmds
    let symByNum = symByNum |> List.rev |> Array.ofList
    let indSymInfo = getIndirecSymInfo cmds reader
    let iSymParse acc sec = parseIndSymbolInfo acc indSymInfo cls symByNum sec
    let iSymByAddr, iSymByName, iSymByNum = Array.fold iSymParse acc secs.SecByNum
    let iSymByNum = iSymByNum |> List.rev |> Array.ofList
    let laSymByName = getLaSymPtrs iSymByNum
    let staticSym, dynamicSym = classifySymbol symByNum
    let struct (linkageTableEntry, stabsStart, stabsEnd) =
        match getStubs cls secs.SecByName with
        | Some s -> 
            let entry = getLinkageTableEntry iSymByNum laSymByName
            struct (entry, s.SecAddr, s.SecAddr + s.SecSize)
        | None -> struct (Map.empty, 0UL, 0UL)
    {
        Sym = genSym symByAddr symByName symByNum
        IndSym = genIndSym iSymByAddr iSymByName iSymByNum
        StaticSymArr = staticSym |> List.rev |> List.toArray
        DynamicSymArr = dynamicSym |> List.rev |> List.toArray
        LinkageTableEntry = linkageTableEntry
        StabsStart = stabsStart
        StabsEnd = stabsEnd
    }

let rec getMainCmd = function
    | [] -> raise FileFormatMismatchException
    | Main m :: _ -> m
    | _ :: tl -> getMainCmd tl

let rec getPageZeroSeg = function
    | [] -> raise FileFormatMismatchException
    | Seg s :: _ when s.SegName = "__PAGEZERO" -> s
    | _ :: tl -> getPageZeroSeg tl

let parseMach offset reader  =
    let machHdr = parseMachHeader reader offset
    let cmds = parseCmds reader offset machHdr
    let libs = parseLibs cmds
    let segs = parseSegment cmds
    let secs = parseSections machHdr.Class cmds reader
    let secs = parseHeaderSection machHdr segs secs
    let symInfo = parseSymbols machHdr.Class cmds secs libs reader
    {
        EntryPoint = (getPageZeroSeg cmds).VMSize + (getMainCmd cmds).EntryOff
        SymInfo = symInfo
        MachHdr = machHdr
        Segment = segs
        Sections = secs
    }

let transFileType = function
    | MHFTExecute -> FileType.ExecutableFile
    | MHFTObject -> FileType.ObjFile
    | MHFTDylib | MHFTFvmlib -> FileType.LibFile
    | MHFTCore -> FileType.CoreFile
    | _ -> FileType.UnknownFile

let tryFindFunctionSymb mach addr =
    if addr >= mach.SymInfo.StabsStart && addr < mach.SymInfo.StabsEnd then
        Map.tryFind addr mach.SymInfo.LinkageTableEntry
        >>= (fun s -> Some s.FuncName)
    else
        let predicate s = isSecSymb s.SymType
        Map.tryFind addr mach.SymInfo.Sym.SymByAddr
        >>= List.tryFind predicate
        >>= (fun s -> Some s.SymName)

let machTypeToSymbKind typ =
    let stabType =
        if typ &&& n_stab <> 0uy then typ |> int |> enum<STABS> |> Some
        else None
    let nType = typ &&& n_type |> int |> enum<NType>
    let extType = typ &&& n_ext = n_ext
    let pextType = typ &&& n_pext = n_pext
    match pextType, stabType, nType, extType with
    | _, _, _ , true -> SymbolKind.ExternFunctionType
    | _, Some STABS.N_FUN, _, _ -> SymbolKind.FunctionType
    | _, Some STABS.N_SO, _, _
    | _, Some STABS.N_OSO, _, _ -> SymbolKind.FileType
    | _, Some STABS.N_BNSYM, _, _
    | _, Some STABS.N_ENSYM, _, _ -> SymbolKind.SectionType
    | _ -> SymbolKind.NoType

let machSymbolToSymbol target (symb: MachSymbol) =
    {
        Address = symb.SymAddr
        Name = symb.SymName
        Kind = machTypeToSymbKind symb.SymType
        Target = target
        LibraryName = machVersionToLibName symb.VerInfo
    }

let getAllStaticSymbols mach =
    mach.SymInfo.StaticSymArr
    |> Array.map (machSymbolToSymbol TargetKind.StaticSymbol)

let getAllDynamicSymbols mach =
    mach.SymInfo.DynamicSymArr
    |> Array.map (machSymbolToSymbol TargetKind.DynamicSymbol)

let secFlagToSectionKind flags =
    match flags &&& section_Type |> int |> enum<SecFlag> with
    | SecFlag.S_NON_LAZY_SYMBOL_POINTERS
    | SecFlag.S_LAZY_SYMBOL_POINTERS
    | SecFlag.S_SYMBOL_STUBS -> SectionKind.LinkageTableSection
    | SecFlag.S_REGULAR -> SectionKind.ExecutableSection
    | _ -> SectionKind.ExtraSection

let machSectionToSection (sec: MachSection) =
    {
        Address = sec.SecAddr
        Kind = secFlagToSectionKind sec.SecFlags
        Size = sec.SecSize
        Name = sec.SecName
    }

let getAllSections mach =
    mach.Sections.SecByNum
    |> Array.map (machSectionToSection)
    |> Array.toSeq

let getSectionsByAddr mach addr =
    match ARMap.tryFindByAddr addr mach.Sections.SecByAddr with
    | Some s -> Seq.singleton (machSectionToSection s)
    | None -> Seq.empty

let getSectionsByName mach name =
    match Map.tryFind name mach.Sections.SecByName with
    | Some s -> Seq.singleton (machSectionToSection s)
    | None -> Seq.empty

type SegFerm =
    | VM_READ = 1
    | VM_WRITE = 2
    | VM_EXECUTE = 4

let convertSegPermission perm =
    let p = if perm &&& SegFerm.VM_READ = SegFerm.VM_READ then 4 else 0
    let p = if perm &&& SegFerm.VM_WRITE = SegFerm.VM_WRITE then p + 2 else p
    if perm &&& SegFerm.VM_EXECUTE = SegFerm.VM_EXECUTE then p + 1 else p

let segCmdToSegment (seg: SegCmd) =
    {
        Address = seg.VMAddr
        Size = seg.VMSize
        Permission = seg.MaxVMProt |> enum<SegFerm> |> convertSegPermission
                                  |> LanguagePrimitives.EnumOfValue
    }

let getAllSegments mach =
    mach.Segment
    |> List.map segCmdToSegment
    |> List.toSeq

let getLinkageTableEntries mach =
    mach.SymInfo.LinkageTableEntry
    |> Map.fold (fun acc _ s -> s :: acc) []
    |> List.sortBy (fun entry -> entry.TrampolineAddress)
    |> List.toSeq

let inline translateAddr mach addr =
    match ARMap.tryFindByAddr addr mach.Sections.SecByAddr with
    | Some s -> Convert.ToInt32 (addr - s.SecAddr + uint64 s.SecOffset)
    | None -> raise InvalidAddrReadException

let initMach bytes =
    let reader = BinReader.Init (bytes)
    if isMachHeader reader startOffset then ()
    else failwith "invalid Mach-O file"
    readEndianness reader startOffset
    |> BinReader.RenewReader reader
    |> parseMach startOffset

// vim: set tw=80 sts=2 sw=2:
