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

module internal B2R2.BinFile.PE

open System
open B2R2
open B2R2.Monads.Maybe
open B2R2.BinFile.PDB
open B2R2.BinFile.FileHelper

let secINIT = ".init"
let secPLT = ".plt"
let secTEXT = ".text"
let secFINI = ".fini"

let secStrings = [
  secINIT
  secPLT
  secTEXT
  secFINI
]

type Machine =
  | IFMachineI386
  | IFMachineAMD64
  | IFMachineIA64
  | IFARM

type Characteristics =
  | IFRelocsStripped
  | IFExecutableImage
  | IFLineNumsStripped
  | IFLocalSymsStripped
  | IFAggresiveWSTrim
  | IFLargeAddressAware
  | IFBytesReversedLO
  | IFI32bitMachine
  | IFDebugStripped
  | IFRemovableRunFromSwap
  | IFNetRunFromSwap
  | IFSystem
  | IFDll
  | IFUpSystemOnly
  | IFBytesReversedHI

type Magic =
  | NTHDR32Magic
  | NTHDR64Magic
  | ROMHDRMagic

type Subsystem =
  | ISUnknown
  | ISNative
  | ISWindowsGUI
  | ISWindowsCUI
  | ISOS2CUI
  | ISPosixCUI
  | ISWindowsCEGUI
  | ISEFIApplication
  | ISEFIBootServiceDriver
  | ISEFIRuntimeDriver
  | ISEFIRom
  | ISXbox
  | ISWindowsBootApplication

type DllCharacteristics =
  | IDDynamicBase
  | IDForceIntegrity
  | IDNXCompat
  | IDNoIsolation
  | IDNoSEH
  | IDNoBind
  | IDWDMDriver
  | IDTerminalServerAware

type SHCharacteristics =
  | ISTypeNoPad
  | ISCntCode
  | ISCntInitData
  | ISCntUninitData
  | ISLnkOther
  | ISLnkInfo
  | ISLnkRemove
  | ISLnkComdat
  | ISNoDeferSpecExc
  | ISGprel
  | ISMemPurgeable
  | ISMemLocked
  | ISMemPreload
  | ISAlign1Bytes
  | ISAlign2Bytes
  | ISAlign4Bytes
  | ISAlign8Bytes
  | ISAlign16Bytes
  | ISAlign32Bytes
  | ISAlign64Bytes
  | ISAlign128Bytes
  | ISAlign256Bytes
  | ISAlign512Bytes
  | ISAlign1024Bytes
  | ISAlign2048Bytes
  | ISAlign4096Bytes
  | ISAlign8192Bytes
  | ISLnkNrelocOvfl
  | ISMemDiscardable
  | ISMemNotCached
  | ISMemNotPaged
  | ISMemShared
  | ISMemExecute
  | ISMemRead
  | ISMemWrite

type DataDirType =
  | Export = 0
  | Import = 1
  | Resource = 2
  | Exception = 3
  | Certificate = 4
  | BaseReloc = 5
  | Debug = 6
  | Arch = 7
  | GlobalPtr = 8
  | TLS = 9
  | LoadConf = 10
  | BoundImport = 11
  | IAT = 12
  | DelayImportDesc = 13
  | CLRRuntimeHdr = 14
  | Reserved = 15

/// COFF File Header.
type ImageFileHeader = {
  Machine                 : Machine
  NumberOfSections        : uint16
  TimeDateStamp           : int
  PointerToSymbolTable    : uint32
  NumberOfSymbols         : uint32
  SizeOfOptionalHeader    : uint16
  Characteristics         : int16
}

/// Optional Header Windows-Specific Fields (Image Only).
type OptionalHeader = {
  Magic                       : Magic
  MajorLinkerVersion          : int
  MinorLinkerVersion          : int
  SizeOfCode                  : uint32
  SizeOfInitializedData       : uint32
  SizeOfUninitializedData     : uint32
  AddressOfEntryPoint         : Addr
  BaseOfCode                  : Addr
  BaseOfData                  : uint32
  ImageBase                   : Addr
  SectionAlignment            : int
  FileAlignment               : int
  MajorOperatingSystemVersion : int16
  MinorOperatingSystemVersion : int16
  MajorImageVersion           : int16
  MinorImageVersion           : int16
  MajorSubsystemVersion       : int16
  MinorSubsystemVersion       : int16
  Win32VersionValue           : int
  SizeOfImage                 : uint32
  SizeOfHeaders               : uint32
  CheckSum                    : int
  Subsystem                   : Subsystem
  DllCharacteristics          : int16
  SizeOfStackReserve          : uint64
  SizeOfStackCommit           : uint64
  SizeOfHeapReserver          : uint64
  SizeOfHeapCommit            : uint64
  LoaderFlags                 : int
  NumberOfRvaAndSizes         : uint32
}

/// Optional Header Data Directories (Image Only).
/// These data directory entries are all loaded into memory so that
/// the system can use them at run time.
type ImageDataDirectory = {
  DirType      : DataDirType
  VirtualAddr  : Addr
  Size         : int
}

type ImageNTHeaders = {
  ImageFileHeader     : ImageFileHeader
  ImageOptionalHdr    : OptionalHeader
  DataDirectoryArray  : ImageDataDirectory []
}

type PEHeader = {
  LFANew        : int
  ImageNTHdrs   : ImageNTHeaders
}

type ImageSectionHeader = {
  Name                : string
  VirtualSize         : int
  VirtualAddr         : Addr
  SizeOfRawData       : uint32
  PointerToRawData    : uint32
  PointerToRelocation : uint32
  PointerToLinenumber : uint32
  NumberOfRelocations : uint16
  NumberOfLinenumbers : uint16
  SHCharacteristics   : uint32
}

type ImageImportDescriptor = {
  OriginalFirstThunk  : Addr
  TimedataStamp       : int
  ForwarderChain      : int
  DLLNameAddr         : Addr
  FirstThunk          : Addr
}

/// IMAGE_IMPORT_BY_NAME.
type ImageImportByName = {
  Addr     : Addr
  Hint     : int16 option
  FuncName : string
}

/// IMAGE_THUNK_DATA
type ThunkData = {
  VMA      : Addr
  VMAData  : ImageImportByName
}

type DLL = {
  DLLName : string
  Thunks  : Map<Addr, ThunkData>
}

type Symbol = {
  SymAddr : Addr
  SymName : string
  LibName : string
  TargetAddr : Addr
}

type TypeOffset = {
  Type    : int
  Offset  : int
}

type ImageBaseRelocation = {
  RelocVirtualAddress : int
  SizeOfBlock         : int
  TypeOffset          : TypeOffset []
}

type ImageSections = {
  SecByNum       : ImageSectionHeader []
  SecAddrMap     : ARMap<ImageSectionHeader>
  SecBindAddrMap : ARMap<ImageSectionHeader>
  SecNameMap     : Map<string, ImageSectionHeader>
}

type Symbols = {
  SymAddrMap : Map<Addr, Symbol>
  SymNameMap : Map<string, Symbol>
}

type PE = {
  PEHdr              : PEHeader
  ImageSecHdrs       : ImageSections
  ImageImpDescriptor : ImageImportDescriptor []
  Import             : DLL []
  Symbols            : Symbols
}

let emptySymMap = {
  SymAddrMap = Map.empty
  SymNameMap = Map.empty
}

let checkTypeDef t n =
  if Enum.IsDefined (t, n) then n else failwithf "%A is Invalid Type %A" n t

let getOptHdrMagic = function
  | 0x010bs -> WordSize.Bit32
  | 0x020bs -> WordSize.Bit64
  | _ -> failwith "Invalid OptHdrMagic"

let getMachine = function
  | 0x014cus -> IFMachineI386
  | 0x8664us -> IFMachineAMD64
  | 0x0200us -> IFMachineIA64
  | 0x01c0us -> IFARM
  | e -> failwithf "Invalid machine type (%x)." e

let getBitTypeFromMagic = function
  | NTHDR32Magic -> WordSize.Bit32
  | NTHDR64Magic -> WordSize.Bit64
  | ROMHDRMagic -> failwith "Cannot know the size from a ROM image."

let getOptionalHdrMagic = function
  | 0x010bs -> NTHDR32Magic
  | 0x020bs -> NTHDR64Magic
  | 0x0107s -> ROMHDRMagic
  | e -> failwithf "Wrong PE type (%x)." e

/// FIXME (MIPS arch)
let getMachineType = function
  | 0x014cus -> Arch.IntelX86
  | 0x8664us | 0x0200us -> Arch.IntelX64
  | 0x01C0us -> Arch.ARMv7
  | 0xAA64us -> Arch.AARCH64
  | 0x0162us | 0x0166us | 0x0168us | 0x0169us
  | 0x0266us | 0x0366us | 0x0466us -> Arch.MIPS32R2
  | _ -> Arch.UnknownISA

let [<Literal>] offsetOfPELfa = 60 // XXX

let parseLfa (reader: BinReader) offset =
  offset + offsetOfPELfa |> reader.PeekUInt32 |> Convert.ToInt32

let isPEHeader (reader: BinReader) offset = (* check both 'MZ' and 'PE' *)
  reader.PeekBytes (2, offset) = [| 0x4Duy; 0x5Auy |] &&
  offset |> parseLfa reader |> reader.PeekUInt32 = 0x00004550u

let parsePEArch (reader: BinReader) offset =
  parseLfa reader offset + 4 |> reader.PeekUInt16 |> getMachineType

let parsePEClass (reader: BinReader) offset =
  parseLfa reader offset + 24 |> reader.PeekInt16 |> getOptHdrMagic

let getSubsystem = function
  | 0x0s -> ISUnknown
  | 0x1s -> ISNative
  | 0x2s -> ISWindowsGUI
  | 0x3s -> ISWindowsCUI
  | 0x5s -> ISOS2CUI
  | 0x7s -> ISPosixCUI
  | 0x9s -> ISWindowsCEGUI
  | 0xas -> ISEFIApplication
  | 0xbs -> ISEFIBootServiceDriver
  | 0xds -> ISEFIRuntimeDriver
  | 0xes -> ISEFIRom
  | 0xfs -> ISXbox
  | 0x10s -> ISWindowsBootApplication
  | e -> failwithf "Wrong subsystem (%x)." e

let private readIFHdrMachine (reader: BinReader) offset =
  let machineOffset = 4
  offset + machineOffset |> reader.PeekUInt16 |> getMachine

let private readIFHdrNumberOfSections (reader: BinReader) offset =
  let numberOfSectionsOffset = 6
  offset + numberOfSectionsOffset |> reader.PeekUInt16

let private readIFHdrTimeDateStamp (reader: BinReader) offset =
  let timeDateStampOffset = 8
  offset + timeDateStampOffset |> reader.PeekInt32

let private readIFHdrPointerToSymbolTable (reader: BinReader) offset =
  let pointerToSymbolTableOffset = 12
  offset + pointerToSymbolTableOffset |> reader.PeekUInt32

let private readIFHdrNumberOfSymbols (reader: BinReader) offset =
  let numberOfSymbolsOffset = 16
  offset + numberOfSymbolsOffset |> reader.PeekUInt32

let private readIFHdrSizeOfOptionalHeader (reader: BinReader) offset =
  let sizeOfOptionalHeaderOffset = 20
  offset + sizeOfOptionalHeaderOffset |> reader.PeekUInt16

let private readIFHdrCharacteristics (reader: BinReader) offset =
  let characteristicsOffset = 22
  offset + characteristicsOffset |> reader.PeekInt16

let parseImageFileHeader (reader: BinReader) lfa =
  {
    Machine = readIFHdrMachine reader lfa
    NumberOfSections = readIFHdrNumberOfSections reader lfa
    TimeDateStamp = readIFHdrTimeDateStamp reader lfa
    PointerToSymbolTable = readIFHdrPointerToSymbolTable reader lfa
    NumberOfSymbols = readIFHdrNumberOfSymbols reader lfa
    SizeOfOptionalHeader = readIFHdrSizeOfOptionalHeader reader lfa
    Characteristics = readIFHdrCharacteristics reader lfa
  }

let parseUIntByMagic (reader: BinReader) pos = function
  | NTHDR32Magic -> reader.PeekUInt32 pos |> uint64
  | NTHDR64Magic -> reader.PeekUInt64 pos
  | ROMHDRMagic -> failwith "Cannot know the size from a ROM image."

let actByMagic (reader: BinReader) pos = function
  | NTHDR32Magic -> reader.PeekUInt32 pos
  | NTHDR64Magic -> 0u
  | ROMHDRMagic -> failwith "Cannot know the size from a ROM image."

let sizeByMagic = function
  | NTHDR32Magic -> 4
  | NTHDR64Magic -> 8
  | ROMHDRMagic -> failwith "Cannot know the size from a ROM image."

let magicToBitType = function
  | NTHDR32Magic -> WordSize.Bit32
  | NTHDR64Magic -> WordSize.Bit64
  | ROMHDRMagic -> failwith "Cannot know the size from a ROM image."

let private readIOHdrmagic (reader: BinReader) offset =
  offset |> reader.PeekInt16 |> getOptionalHdrMagic

let private readIOHdrMajorLinkerVer (reader: BinReader) offset =
  let majorLinkerVerOffset = 2
  offset + majorLinkerVerOffset |> reader.PeekByte |> int

let private readIOHdrMinorLinkerVer (reader: BinReader) offset =
  let minorLinkerVerOffset = 3
  offset + minorLinkerVerOffset |> reader.PeekByte |> int

let private readIOHdrSizeOfCode (reader: BinReader) offset =
  let sizeOfCodeOffset = 4
  offset + sizeOfCodeOffset |> reader.PeekUInt32

let private readIOHdrSizeOfInitData (reader: BinReader) offset =
  let sizeOfInitDataOffset = 8
  offset + sizeOfInitDataOffset |> reader.PeekUInt32

let private readIOHdrSizeOfUninitData (reader: BinReader) offset =
  let sizeOfUninitDataOffset = 12
  offset + sizeOfUninitDataOffset |> reader.PeekUInt32

let private readIOHdrAddrOfEntryPoint (reader: BinReader) offset =
  let addrOfEntryPointOffset = 16
  offset + addrOfEntryPointOffset |> reader.PeekUInt32 |> uint64

let private readIOHdrBaseOfCode (reader: BinReader) offset =
  let baseOfCodeOffset = 20
  offset + baseOfCodeOffset |> reader.PeekUInt32 |> uint64

let private readIOHdrBaseOfData (reader: BinReader) bitType offset =
  let baseOfDataOffset = 24
  if bitType = WordSize.Bit64 then 0u
  else offset + baseOfDataOffset |> reader.PeekUInt32

let private readIOHdrImageBase (reader: BinReader) bitType offset =
  let imageBaseOffset = if bitType = WordSize.Bit32 then 28 else 24
  offset + imageBaseOffset |> peekUIntOfType reader bitType

let private readIOHdrSectionAlignment (reader: BinReader) offset =
  let sectionAlignmentOffset = 32
  offset + sectionAlignmentOffset |> reader.PeekInt32

let private readIOHdrFileAlignment (reader: BinReader) offset =
  let fileAlignmentOffset = 36
  offset + fileAlignmentOffset |> reader.PeekInt32

let private readIOHdrMajorOSVer (reader: BinReader) offset =
  let majorOSVerOffset = 40
  offset + majorOSVerOffset |> reader.PeekInt16

let private readIOHdrMinorOSVer (reader: BinReader) offset =
  let minorOSVerOffset = 42
  offset + minorOSVerOffset |> reader.PeekInt16

let private readIOHdrMajorImageVers (reader: BinReader) offset =
  let majorImageVersOffset = 44
  offset + majorImageVersOffset |> reader.PeekInt16

let private readIOHdrMinorImageVers (reader: BinReader) offset =
  let minorImageVersOffset = 46
  offset + minorImageVersOffset |> reader.PeekInt16

let private readIOHdrMajorSubsystemVers (reader: BinReader) offset =
  let majorSubsystemVersOffset = 48
  offset + majorSubsystemVersOffset |> reader.PeekInt16

let private readIOHdrMinorSubsystemVers (reader: BinReader) offset =
  let majorSubsystemVersOffset = 50
  offset + majorSubsystemVersOffset |> reader.PeekInt16

let private readIOHdrWin32VersionValue (reader: BinReader) offset =
  let win32VersionValueOffset = 52
  offset + win32VersionValueOffset |> reader.PeekInt32

let private readIOHdrSizeOfImage (reader: BinReader) offset =
  let sizeOfImageOffset = 56
  offset + sizeOfImageOffset |> reader.PeekUInt32

let private readIOHdrSizeOfHeaders (reader: BinReader) offset =
  let sizeOfHeadersOffset = 60
  offset + sizeOfHeadersOffset |> reader.PeekUInt32

let private readIOHdrCheckSum (reader: BinReader) offset =
  let checkSumOffset = 64
  offset + checkSumOffset |> reader.PeekInt32

let private readIOHdrSubsystem (reader: BinReader) offset =
  let subsystemOffset = 68
  offset + subsystemOffset |> reader.PeekInt16 |> getSubsystem

let private readIOHdrDllCharacteristics (reader: BinReader) offset =
  let dllCharacteristicsOffset = 70
  offset + dllCharacteristicsOffset |> reader.PeekInt16

let private readIOHdrSizeOfStackReserve reader bitType offset =
  let sizeOfStackReserveOffset = 72
  offset + sizeOfStackReserveOffset |> peekUIntOfType reader bitType

let private readIOHdrSizeOfStackCommit reader bitType offset =
  let sizeOfStackCommitOffset = if bitType = WordSize.Bit32 then 76 else 80
  offset + sizeOfStackCommitOffset |> peekUIntOfType reader bitType

let private readIOHdrSizeOfHeapReserver reader bitType offset =
  let sizeOfHeapReserverOffset = if bitType = WordSize.Bit32 then 80 else 88
  offset + sizeOfHeapReserverOffset |> peekUIntOfType reader bitType

let private readIOHdrSizeOfHeapCommit reader  bitType offset =
  let sizeOfHeapCommitOffset = if bitType = WordSize.Bit32 then 84 else 96
  offset + sizeOfHeapCommitOffset |> peekUIntOfType reader bitType

let private readIOHdrLoaderFlags (reader: BinReader) bitType offset =
  let loaderFlagsOffset = if bitType = WordSize.Bit32 then 88 else 104
  offset + loaderFlagsOffset |> reader.PeekInt32

let private readIOHdrNumberOfRvaAndSizes (reader: BinReader) bitType offset =
  let numberOfRvaAndSizesOffset = if bitType = WordSize.Bit32 then 92 else 108
  offset + numberOfRvaAndSizesOffset |> reader.PeekUInt32

let parseImageOptionalHeader (reader: BinReader) lfa =
  let imageOptionalHeaderOffset = 24
  let offset = lfa + imageOptionalHeaderOffset
  let magic = readIOHdrmagic reader offset
  let bitType = magicToBitType magic
  {
    Magic = magic
    MajorLinkerVersion = readIOHdrMajorLinkerVer reader offset
    MinorLinkerVersion = readIOHdrMinorLinkerVer reader offset
    SizeOfCode = readIOHdrSizeOfCode reader offset
    SizeOfInitializedData = readIOHdrSizeOfInitData reader offset
    SizeOfUninitializedData = readIOHdrSizeOfUninitData reader offset
    AddressOfEntryPoint = readIOHdrAddrOfEntryPoint reader offset
    BaseOfCode = readIOHdrBaseOfCode reader offset
    BaseOfData = readIOHdrBaseOfData reader bitType offset
    ImageBase = readIOHdrImageBase reader bitType offset
    SectionAlignment = readIOHdrSectionAlignment reader offset
    FileAlignment = readIOHdrFileAlignment reader offset
    MajorOperatingSystemVersion = readIOHdrMajorOSVer reader offset
    MinorOperatingSystemVersion = readIOHdrMinorOSVer reader offset
    MajorImageVersion = readIOHdrMajorImageVers reader offset
    MinorImageVersion = readIOHdrMinorImageVers reader offset
    MajorSubsystemVersion = readIOHdrMajorSubsystemVers reader offset
    MinorSubsystemVersion = readIOHdrMinorSubsystemVers reader offset
    Win32VersionValue = readIOHdrWin32VersionValue reader offset
    SizeOfImage = readIOHdrSizeOfImage reader offset
    SizeOfHeaders = readIOHdrSizeOfHeaders reader offset
    CheckSum = readIOHdrCheckSum reader offset
    Subsystem = readIOHdrSubsystem reader offset
    DllCharacteristics = readIOHdrDllCharacteristics reader offset
    SizeOfStackReserve = readIOHdrSizeOfStackReserve reader bitType offset
    SizeOfStackCommit = readIOHdrSizeOfStackCommit reader bitType offset
    SizeOfHeapReserver = readIOHdrSizeOfHeapReserver reader bitType offset
    SizeOfHeapCommit = readIOHdrSizeOfHeapCommit reader  bitType offset
    LoaderFlags = readIOHdrLoaderFlags reader bitType offset
    NumberOfRvaAndSizes = readIOHdrNumberOfRvaAndSizes reader bitType offset
  }

let parseImageDataDirectory offset (reader: BinReader) n =
  {
    DirType = n |> enum<DataDirType>
    VirtualAddr = reader.PeekUInt32 offset |> uint64
    Size = reader.PeekInt32 (offset + 4)
  }

let parseDataDirectoryArray imageOptionalHdr reader lfa =
  let dataDirArrOffset =
    if magicToBitType imageOptionalHdr.Magic = WordSize.Bit32
      then lfa + 120 else lfa + 136
  let rec getDataDir acc offset n =
    if n >= 16 then acc |> List.rev |> List.toArray
    else
      let dataDirectory = parseImageDataDirectory offset reader n
      getDataDir (dataDirectory :: acc) (offset + 8) (n + 1)
  getDataDir [] dataDirArrOffset 0

let parseImageNTHeaders reader lfa =
  let imageFileHeader = parseImageFileHeader reader lfa
  let imageOptionalHdr = parseImageOptionalHeader reader lfa
  let imageDataDirs = parseDataDirectoryArray imageOptionalHdr reader lfa
  {
    ImageFileHeader = imageFileHeader
    ImageOptionalHdr = imageOptionalHdr
    DataDirectoryArray = imageDataDirs
  }

let parsePEHeader reader offset =
  let lfa = parseLfa reader offset
  let imageNTHdrs = parseImageNTHeaders reader lfa
  { LFANew = lfa; ImageNTHdrs = imageNTHdrs }

let private readSecName (reader: BinReader) offset =
  reader.PeekBytes (8, offset) |> Array.filter ((<>)0uy)
  |> Text.Encoding.ASCII.GetString

let private readSecSize (reader: BinReader) offset =
  let secSizeOffset = 8
  offset + secSizeOffset |> reader.PeekInt32

let private readSecAddr (reader: BinReader) offset =
  let secAddrOffset = 12
  offset + secAddrOffset |> reader.PeekInt32 |> uint64

let private readSecRawDataSize (reader: BinReader) offset =
  let secRawDataSizeOffset = 16
  offset + secRawDataSizeOffset |> reader.PeekUInt32

let private readSecPointerToRawData (reader: BinReader) offset =
  let secPointerToRawDataOffset = 20
  offset + secPointerToRawDataOffset |> reader.PeekUInt32

let private readSecPointerToRelocation (reader: BinReader) offset =
  let secPointerToRelocationOffset = 24
  offset + secPointerToRelocationOffset |> reader.PeekUInt32

let private readSecPointerToLinenumber (reader: BinReader) offset =
  let secPointerToLinenumberOffset = 28
  offset + secPointerToLinenumberOffset |> reader.PeekUInt32

let private readSecNumberOfRelocations (reader: BinReader) offset =
  let secNumberOfRelocationsOffset = 32
  offset + secNumberOfRelocationsOffset |> reader.PeekUInt16

let private readSecNumberOfLinenumbers (reader: BinReader) offset =
  let secNumberOfLinenumbersOffset = 34
  offset + secNumberOfLinenumbersOffset |> reader.PeekUInt16

let private readSecSHCharacteristics (reader: BinReader) offset =
  let secSHCharacteristicsOffset = 36
  offset + secSHCharacteristicsOffset |> reader.PeekUInt32

let parseSection reader offset =
  {
    Name                = readSecName reader offset
    VirtualSize         = readSecSize reader offset
    VirtualAddr         = readSecAddr reader offset
    SizeOfRawData       = readSecRawDataSize reader offset
    PointerToRawData    = readSecPointerToRawData reader offset
    PointerToRelocation = readSecPointerToRelocation reader offset
    PointerToLinenumber = readSecPointerToLinenumber reader offset
    NumberOfRelocations = readSecNumberOfRelocations reader offset
    NumberOfLinenumbers = readSecNumberOfLinenumbers reader offset
    SHCharacteristics   = readSecSHCharacteristics reader offset
  }

let parseSecHdrs reader pHdr =
  let bitType = pHdr.ImageNTHdrs.ImageOptionalHdr.Magic |> magicToBitType
  let offset = if bitType = WordSize.Bit32 then pHdr.LFANew + 248
               else pHdr.LFANew + 264
  let rec parseSecHdr sNum acc offset =
    if sNum = 0us then List.rev acc
    else
      let sec = parseSection reader offset
      let nextSecOffset = offset + 40
      parseSecHdr (sNum - 1us) (sec :: acc) nextSecOffset
  parseSecHdr pHdr.ImageNTHdrs.ImageFileHeader.NumberOfSections [] offset

let makeSecHdrsMap pHdr sHdrs =
  let acc = struct (ARMap.empty, ARMap.empty, Map.empty)
  let folder acc sHdr =
    let struct (addrMap, bindAddrMap, nameMap) = acc
    let ib = pHdr.ImageNTHdrs.ImageOptionalHdr.ImageBase
    let minVal = sHdr.VirtualAddr |> uint64
    let maxVal = minVal + (sHdr.VirtualSize |> uint64)
    let secAddrMap = ARMap.addRange minVal maxVal sHdr addrMap
    let secBindAddrMap =
      ARMap.addRange (ib + minVal) (ib + maxVal) sHdr bindAddrMap
    let secNameMap = Map.add sHdr.Name sHdr nameMap
    struct (secAddrMap, secBindAddrMap, secNameMap)
  let struct (addrMap, bindAddrMap, nameMap) = List.fold folder acc sHdrs
  {
    SecByNum = sHdrs |> List.toArray
    SecAddrMap = addrMap
    SecBindAddrMap = bindAddrMap
    SecNameMap = nameMap
  }

let parseImportDirectory (reader: BinReader) pos = {
    OriginalFirstThunk  = reader.PeekUInt32 pos |> uint64
    TimedataStamp       = reader.PeekInt32 (pos + 4)
    ForwarderChain      = reader.PeekInt32 (pos + 8)
    DLLNameAddr         = reader.PeekUInt32 (pos + 12) |> uint64
    FirstThunk          = reader.PeekUInt32 (pos + 16) |> uint64
  }

let getRawAddr vAddr isecs =
  match ARMap.tryFindByAddr vAddr isecs with
  | Some sec -> Some <| (uint64 sec.PointerToRawData) + vAddr - sec.VirtualAddr
  | None -> None

let getAddr pHdr idx iSecHdr =
  let dataDir = pHdr.ImageNTHdrs.DataDirectoryArray.[ idx ]
  getRawAddr dataDir.VirtualAddr iSecHdr

let getImageImportDescriptors reader pos =
  let predicate tbl =
    tbl.OriginalFirstThunk = 0UL && tbl.TimedataStamp = 0
    && tbl.ForwarderChain = 0 && tbl.DLLNameAddr = 0UL && tbl.FirstThunk = 0UL
  let rec loop acc pos =
    let tbl = parseImportDirectory reader pos
    if predicate tbl then acc else loop (tbl :: acc) (pos + 20)
  loop [] pos |> List.rev |> List.toArray

let parseImageImportDescriptor reader pHdr iSecHdr =
  let ilmpDesOffset = getAddr pHdr (int DataDirType.Import) iSecHdr.SecAddrMap
  match ilmpDesOffset with
  | Some o -> getImageImportDescriptors reader (Convert.ToInt32 o)
  | None -> Array.empty

let parseName (reader: BinReader) pos = // FIXME refactor?
  let rec loop acc pos =
    let byte = reader.PeekByte pos
    if byte = 0uy then acc else loop (byte :: acc) (pos + 1)
  loop [] pos |> List.rev |> List.toArray |> Text.Encoding.ASCII.GetString

let parseImageImportByName (reader: BinReader) addr iSecHdr =
  match getRawAddr addr iSecHdr with
  | Some pos ->
    let pos = Convert.ToInt32 pos
    let hint, name = reader.PeekInt16 pos, parseName reader (pos + 2)
    { Addr = addr; Hint = Some hint; FuncName = name }
  | None -> { Addr = addr; Hint = None; FuncName = "" }

let parseAddrData reader pHdr pos fstThunk =
  let magic = pHdr.ImageNTHdrs.ImageOptionalHdr.Magic
  let sz = sizeByMagic magic
  let fstThunk, offset =
    if magic = NTHDR32Magic then (0x400000UL + fstThunk), 4UL
    elif magic = NTHDR64Magic then (0x140000000UL + fstThunk), 8UL
    else failwith "Cannot get offset size."
  let rec loop acc pos thunk =
    let (_, addr2) as addr = thunk, parseUIntByMagic reader pos magic
    if addr2 = 0UL then acc else loop (addr :: acc) (pos + sz) (thunk + offset)
  loop [] pos fstThunk

let makeThunkMap reader iSecHdr addrLst =
  let makeThunkMapAux reader (addr1, addr2) map =
    let vmaData = parseImageImportByName reader addr2 iSecHdr
    let thunk = { VMA = addr1; VMAData = vmaData }
    Map.add addr2 thunk map
  List.fold (fun map addr -> makeThunkMapAux reader addr map) Map.empty addrLst

let getThunks reader sHdr pHdr descriptor =
  let thunk = descriptor.FirstThunk
  match getRawAddr thunk sHdr with
  | Some pos -> parseAddrData reader pHdr (Convert.ToInt32 pos) thunk
                |> makeThunkMap reader sHdr
  | None -> Map.empty

let parseDLLInfo reader descriptor iSecHdr pHdr =
  match getRawAddr descriptor.DLLNameAddr iSecHdr with
  | Some pos -> { DLLName = parseName reader (Convert.ToInt32 pos)
                  Thunks = getThunks reader iSecHdr pHdr descriptor }
  | None -> failwith "Invalid DLL info"

let parseDLL reader iImpDes iSecHdr pHdr =
  let pDLL descriptor = parseDLLInfo reader descriptor iSecHdr pHdr
  Array.map pDLL iImpDes

let maketypeOffsetMap typeoffset =
  { Type = (typeoffset &&& 0xf000) >>> 12; Offset = typeoffset &&& 0x0fff }

let makeSymbols dlls =
  let parseSymName dllName data map =
    let sym = {
                SymAddr = data.VMA
                SymName = data.VMAData.FuncName
                LibName = dllName
                TargetAddr = data.VMAData.Addr
              }
    let nameMap = if data.VMAData.FuncName = "" then map.SymNameMap
                  else Map.add data.VMAData.FuncName sym map.SymNameMap
    {
      SymAddrMap = Map.add sym.SymAddr sym map.SymAddrMap
      SymNameMap = nameMap
    }
  let parseSym map dll =
    Map.fold (fun map _ data -> parseSymName dll.DLLName data map) map dll.Thunks
  Array.fold parseSym emptySymMap dlls

let parsePE reader offset =
  let pHdr = parsePEHeader reader offset
  let iSecHdr = parseSecHdrs reader pHdr |> makeSecHdrsMap pHdr
  let iImpDes = parseImageImportDescriptor reader pHdr iSecHdr
  let dlls = parseDLL reader iImpDes iSecHdr.SecAddrMap pHdr
  let symbol = makeSymbols dlls
  {
    PEHdr              = pHdr
    ImageSecHdrs       = iSecHdr
    ImageImpDescriptor = iImpDes
    Import             = dlls
    Symbols            = symbol
  }

let transFileType = function
  | flags when flags &&& 0x2s <> 0s -> FileType.ExecutableFile
  | flags when flags &&& 0x2000s <> 0s -> FileType.LibFile
  | _ -> FileType.UnknownFile

let parsePdbSymbols pe (pdb: PDBSymNumMap) =
  let acc = Map.empty, Map.empty, []
  let iBase = pe.PEHdr.ImageNTHdrs.ImageOptionalHdr.ImageBase
  let genSymbol (addrMap, nameMap, lst) sec (sym: Sym) =
    let addr = iBase + sec.VirtualAddr + (uint64 sym.Offset)
    let sym = {sym with Addr = addr }
    Map.add addr sym addrMap,
    Map.add sym.Name sym nameMap,
    sym :: lst
  let loop acc _ (sym: Sym) =
    let secNum = int sym.Segment - 1
    match Array.tryItem secNum pe.ImageSecHdrs.SecByNum with
    | Some sec -> genSymbol acc sec sym
    | None -> acc
  let aMap, nMap, lst = Map.fold loop acc pdb
  {
    PDBAddrMap = aMap
    PDBNameMap = nMap
    PDBSymArr = List.rev lst |> List.toArray
  }

let findSymFromPDB addr pdb =
  Map.tryFind addr pdb.PDBAddrMap >>= (fun s -> Some s.Name)

let findSymFromPE addr pe =
  Map.tryFind addr pe.Symbols.SymAddrMap >>= (fun s -> Some s.SymName)

let tryFindFunctionSymbolName pe pdb addr =
  match findSymFromPDB addr pdb with
  | None -> findSymFromPE addr pe
  | name -> name

let initPDB (execpath: string) rawpdb =
  match rawpdb with
  | None ->
    let pdbPath = IO.Path.ChangeExtension (execpath, "pdb")
    if IO.File.Exists pdbPath then IO.File.ReadAllBytes pdbPath |> parsePDB
    else PDB.emptyPDB
  | Some rawpdb -> parsePDB rawpdb

let pdbTypeToSymbKind = function
  | SymFlags.Function -> SymbolKind.FunctionType
  | _ -> SymbolKind.NoType

let peSymbolToSymbol acc (sym: Symbol) target =
    {
    Address = sym.SymAddr
    Name = sym.SymName
    Kind = SymbolKind.FunctionType
    Target = target
    LibraryName = sym.LibName
    } :: acc

let pdbSymbolToSymbol acc sym target =
  if sym.Segment = 2us then acc
  else
    {
    Address = sym.Addr
    Name = sym.Name
    Kind = pdbTypeToSymbKind sym.Flags
    Target = target
    LibraryName = ""
    } :: acc

let getAllStaticSymbols pdb =
  pdb.PDBSymArr
  |> Array.fold (fun a s -> pdbSymbolToSymbol a s TargetKind.StaticSymbol) []
  |> List.toArray

let getAllDynamicSymbols pe =
  pe.Symbols.SymAddrMap
  |> Map.fold (fun a _ s -> peSymbolToSymbol a s TargetKind.DynamicSymbol) []
  |> List.toArray

let secFlagToSectionKind flags =
  if flags &&& 0x20000000u = 0x20000000u then
    SectionKind.ExecutableSection
  elif flags &&& 0x80000000u = 0x80000000u  then
    SectionKind.WritableSection
  else
    SectionKind.ExtraSection

let peSectionToSection pe (sec: ImageSectionHeader) =
  let iBase = pe.PEHdr.ImageNTHdrs.ImageOptionalHdr.ImageBase
  {
    Address = sec.VirtualAddr + iBase
    Kind = secFlagToSectionKind sec.SHCharacteristics
    Size = sec.VirtualSize |> uint64
    Name = sec.Name
  }

let getAllSections pe =
  pe.ImageSecHdrs.SecByNum
  |> Array.map (peSectionToSection pe)
  |> Array.toSeq

let getSectionsByAddr pe addr =
  match ARMap.tryFindByAddr addr pe.ImageSecHdrs.SecAddrMap with
  | Some s -> Seq.singleton (peSectionToSection pe s)
  | None -> Seq.empty

let getSectionsByName pe name =
  match Map.tryFind name pe.ImageSecHdrs.SecNameMap with
  | Some s -> Seq.singleton (peSectionToSection pe s)
  | None -> Seq.empty

let getSegPermission flags =
  let p = if flags &&& 0x20000000u = 0x20000000u then 1 else 0
  let p = if flags &&& 0x40000000u = 0x40000000u then p + 4 else p
  if flags &&& 0x80000000u = 0x80000000u then p + 2 else p


let progHdrToSegment pe sec =
  let iBase = pe.PEHdr.ImageNTHdrs.ImageOptionalHdr.ImageBase
  {
    Address = sec.VirtualAddr + iBase
    Size = sec.VirtualSize |> uint64
    Permission = getSegPermission sec.SHCharacteristics
                 |> LanguagePrimitives.EnumOfValue
  }

let getAllSegments pe =
  pe.ImageSecHdrs.SecByNum
  |> Array.map (progHdrToSegment pe)
  |> Array.toSeq

let getLinkageTableEntries pe =
  let iBase = pe.PEHdr.ImageNTHdrs.ImageOptionalHdr.ImageBase
  let create addr (symb: Symbol) =
    {
      FuncName = symb.SymName
      LibraryName = symb.LibName
      TrampolineAddress = addr
      TableAddress = symb.TargetAddr + iBase
    }
  pe.Symbols.SymAddrMap
  |> Map.fold (fun acc addr s -> create addr s :: acc) []
  |> List.sortBy (fun entry -> entry.TrampolineAddress)
  |> List.toSeq

let initPE bytes =
  let reader = BinReader.Init (bytes)
  if isPEHeader reader startOffset then ()
  else raise FileFormatMismatchException
  parsePE reader startOffset

let inline isValidAddr pe addr =
  match ARMap.tryFindByAddr addr pe.ImageSecHdrs.SecBindAddrMap with
  | Some _ -> true
  | None -> false

let inline translateAddr pe addr =
  if isValidAddr pe addr then
    let sec = ARMap.findByAddr addr pe.ImageSecHdrs.SecBindAddrMap
    let iBase = pe.PEHdr.ImageNTHdrs.ImageOptionalHdr.ImageBase
    addr - (iBase + sec.VirtualAddr) + (uint64 sec.PointerToRawData)
    |> Convert.ToInt32
  else raise InvalidAddrReadException

// vim: set tw=80 sts=2 sw=2:
