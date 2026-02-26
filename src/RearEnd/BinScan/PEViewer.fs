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

module internal B2R2.RearEnd.BinScan.PEViewer

open System.Reflection.PortableExecutable
open B2R2
open B2R2.Logging
open B2R2.FrontEnd.BinFile
open B2R2.RearEnd.Utils

let dumpFileHeader _ (pe: PEBinFile) =
  let hdr = pe.PEHeaders.CoffHeader
  let machine = hdr.Machine
  let machineStr = $"{machine} ({HexString.ofUInt64 (uint64 machine)})"
  let ptrToSymTab = HexString.ofInt32 hdr.PointerToSymbolTable
  let sizeOfOptHdr = HexString.ofInt16 hdr.SizeOfOptionalHeader
  let characteristics = uint32 hdr.Characteristics |> HexString.ofUInt32
  resetToDefaultTwoColumnConfig ()
  printsr [| "Machine:"; machineStr |]
  printsr [| "Number of sections:"; hdr.NumberOfSections.ToString() |]
  printsr [| "Time date stamp:"; hdr.TimeDateStamp.ToString() |]
  printsr [| "Pointer to symbol table:"; ptrToSymTab |]
  printsr [| "Size of optional header:"; sizeOfOptHdr |]
  printsr [| "Characteristics:"; characteristics |]
  for flag in enumerateFlags hdr.Characteristics do
    printsr [| ""; String.ofEnum flag |]
  printsn ""

let makeSectionHeadersFormatVerbose addrColumn =
  [| LeftAligned 4
     addrColumn
     addrColumn
     LeftAligned 24
     LeftAligned 8
     LeftAligned 8
     LeftAligned 8
     LeftAligned 8
     LeftAligned 8
     LeftAligned 8
     LeftAligned 8
     LeftAligned 8
     LeftAligned 15 |]

let makeSectionHeadersTableHeaderVerbose () =
  [| "Num"
     "Start"
     "End"
     "Name"
     "VirtSize"
     "VirtAddr"
     "RawSize"
     "RawPtr"
     "RelocPtr"
     "LineNPtr"
     "RelNum"
     "LineNum"
     "Characteristics" |]

let selectSize (s: SectionHeader) =
  if s.VirtualSize = 0 then s.SizeOfRawData
  else s.VirtualSize

let enumSectionCharacteristics (ch: SectionCharacteristics) =
  if uint64 ch = 0UL then
    [| SectionCharacteristics.TypeReg |]
  else
    enumerateFlags ch
    |> Array.filter (fun flag -> uint64 flag <> 0UL)

let dumpSectionHeadersVerbose (pe: PEBinFile) wordSize addrColumn =
  setTableColumnFormats <| makeSectionHeadersFormatVerbose addrColumn
  printDoubleHorizontalRule ()
  printsr <| makeSectionHeadersTableHeaderVerbose ()
  printSingleHorizontalRule ()
  for i in 0 .. pe.SectionHeaders.Length - 1 do
    let s = pe.SectionHeaders[i]
    let startAddr = pe.BaseAddress + uint64 s.VirtualAddress
    let size = uint64 (selectSize s)
    let characteristics = uint64 s.SectionCharacteristics |> HexString.ofUInt64
    printsr [| String.wrapSqrdBracket (i.ToString())
               Addr.toString wordSize startAddr
               Addr.toString wordSize (startAddr + size - uint64 1)
               normalizeEmpty s.Name
               HexString.ofUInt64 (uint64 s.VirtualSize)
               HexString.ofUInt64 (uint64 s.VirtualAddress)
               HexString.ofUInt64 (uint64 s.SizeOfRawData)
               HexString.ofUInt64 (uint64 s.PointerToRawData)
               HexString.ofUInt64 (uint64 s.PointerToRelocations)
               HexString.ofUInt64 (uint64 s.PointerToLineNumbers)
               s.NumberOfRelocations.ToString()
               s.NumberOfLineNumbers.ToString()
               characteristics |]
    for ch in enumSectionCharacteristics s.SectionCharacteristics do
      let str = String.ofEnum ch
      printsr [| ""; ""; ""; ""; ""; ""; ""; ""; ""; ""; ""; ""; str |]
  printDoubleHorizontalRule ()
  printsn ""

let dumpSectionHeadersSimple (pe: PEBinFile) wordSize addrColumn =
  let colfmts = [| LeftAligned 4; addrColumn; addrColumn; LeftAligned 24 |]
  setTableColumnFormats colfmts
  printDoubleHorizontalRule ()
  printsr [| "Num"; "Start"; "End"; "Name" |]
  printSingleHorizontalRule ()
  for i in 0 .. pe.SectionHeaders.Length - 1 do
    let s = pe.SectionHeaders[i]
    let addr = uint64 s.VirtualAddress + (pe :> IBinFile).BaseAddress
    printsr [| String.wrapSqrdBracket (i.ToString())
               Addr.toString wordSize addr
               Addr.toString wordSize (addr + uint64 s.VirtualSize - 1UL)
               normalizeEmpty s.Name |]
  printDoubleHorizontalRule ()
  printsn ""

let dumpSectionHeaders (opts: BinScanOpts) (pe: PEBinFile) =
  let addrColumn = columnWidthOfAddr pe |> LeftAligned
  let wordSize = (pe :> IBinFile).ISA.WordSize
  if opts.Verbose then dumpSectionHeadersVerbose pe wordSize addrColumn
  else dumpSectionHeadersSimple pe wordSize addrColumn

let dumpSectionDetails (secName: string) (pe: PEBinFile) =
  let idx = pe.SectionHeaders |> Array.tryFindIndex (fun s -> s.Name = secName)
  match idx with
  | Some idx ->
    let sec = pe.SectionHeaders[idx]
    let virtualSize = uint64 sec.VirtualSize |> HexString.ofUInt64
    let virtualAddr = uint64 sec.VirtualAddress |> HexString.ofUInt64
    let sizeOfRawData = uint64 sec.SizeOfRawData |> HexString.ofUInt64
    let ptrToRawData = uint64 sec.PointerToRawData |> HexString.ofUInt64
    let ptrToRelocs = uint64 sec.PointerToRelocations |> HexString.ofUInt64
    let ptrToLineNums = uint64 sec.PointerToLineNumbers |> HexString.ofUInt64
    let characteristics = uint64 sec.SectionCharacteristics
    resetToDefaultTwoColumnConfig ()
    printsr [| "Section number:"; String.wrapSqrdBracket (idx.ToString()) |]
    printsr [| "Section name:"; sec.Name |]
    printsr [| "Virtual size:"; virtualSize |]
    printsr [| "Virtual address:"; virtualAddr |]
    printsr [| "Size of raw data:"; sizeOfRawData |]
    printsr [| "Pointer to raw data:"; ptrToRawData |]
    printsr [| "Pointer to relocations:"; ptrToRelocs |]
    printsr [| "Pointer to line numbers:"; ptrToLineNums |]
    printsr [| "Number of relocations:"; sec.NumberOfRelocations.ToString() |]
    printsr [| "Number of line numbers:"; sec.NumberOfLineNumbers.ToString() |]
    printsr [| "Characteristics:"; HexString.ofUInt64 characteristics |]
    for ch in enumSectionCharacteristics sec.SectionCharacteristics do
      printsr [| ""; String.ofEnum ch |]
    printsn ""
  | None ->
    printsr [| ""; normalizeEmpty "" |]
    printsn ""

let dumpSymbol wordSize (symb: PE.Symbol) =
  printsr [| Addr.toString wordSize symb.Address
             String.wrapSqrdBracket $"{symb.Segment}"
             normalizeEmpty symb.Name |]

let dumpSymbols _ (pe: PEBinFile) =
  let addrColumn = columnWidthOfAddr pe |> LeftAligned
  setTableColumnFormats [| addrColumn; LeftAligned 10; LeftAligned 50 |]
  printDoubleHorizontalRule ()
  printsr [| "Address"; "SectionID"; "Name" |]
  printSingleHorizontalRule ()
  for s in pe.Symbols.SymbolArray do
    dumpSymbol (pe :> IBinFile).ISA.WordSize s
  printDoubleHorizontalRule ()
  printsn ""

let dumpRelocs _ (pe: PEBinFile) =
  let addrColumn = columnWidthOfAddr pe |> LeftAligned
  setTableColumnFormats [| addrColumn; LeftAligned 50 |]
  printDoubleHorizontalRule ()
  printsr [| "Address"; "Relocation Type" |]
  printSingleHorizontalRule ()
  for block in pe.RelocBlocks do
    for entry in block.Entries do
      let addr = uint64 block.PageRVA + uint64 entry.Offset
      printsr [| Addr.toString (pe :> IBinFile).ISA.WordSize addr
                 $"{entry.Type}" |]
  printDoubleHorizontalRule ()
  printsn ""

let dumpFunctions _ (pe: PEBinFile) =
  let addrColumn = columnWidthOfAddr pe |> LeftAligned
  setTableColumnFormats [| addrColumn; LeftAligned 50 |]
  printDoubleHorizontalRule ()
  printsr [| "Address"; "Function" |]
  printSingleHorizontalRule ()
  for addr in (pe :> IBinFile).GetFunctionAddresses() do
    match (pe :> IBinFile).TryFindName addr with
    | Ok name ->
      printsr [| Addr.toString (pe :> IBinFile).ISA.WordSize addr; name |]
    | Error _ ->
      ()
  printDoubleHorizontalRule ()
  printsn ""

let inline addrFromRVA baseAddr rva = uint64 rva + baseAddr

let dumpImportedSymbol pe addr name hint libName =
  printsr [| Addr.toString (pe :> IBinFile).ISA.WordSize addr
             normalizeEmpty name
             $"{hint:x}"
             libName |]

let dumpImports _ (pe: PEBinFile) =
  let addrColumn = columnWidthOfAddr pe |> LeftAligned
  setTableColumnFormats
    [| addrColumn; LeftAligned 50; LeftAligned 12; LeftAligned 15 |]
  printDoubleHorizontalRule ()
  printsr [| "Address"; "Name"; "Ordinal/Hint"; "Lib Name" |]
  printSingleHorizontalRule ()
  pe.ImportedSymbols
  |> Map.iter (fun rva imp ->
    let addr = pe.BaseAddress + uint64 rva
    match imp with
    | PE.ByOrdinal(ord, dllname) ->
      let name = String.wrapSqrdBracket $"{ord}"
      dumpImportedSymbol pe addr name ord dllname
    | PE.ByName(hint, fn, dllname) ->
      dumpImportedSymbol pe addr fn hint dllname)
  printDoubleHorizontalRule ()
  printsn ""

let dumpExports _ (pe: PEBinFile) =
  let addrColumn = columnWidthOfAddr pe |> LeftAligned
  setTableColumnFormats [| addrColumn; LeftAligned 50 |]
  printDoubleHorizontalRule ()
  printsr [| "Address"; "Name" |]
  printSingleHorizontalRule ()
  pe.ExportedSymbols.Exports
  |> Map.iter (fun addr names ->
    for name in names do
      printsr [| Addr.toString (pe :> IBinFile).ISA.WordSize addr
                 normalizeEmpty name |])
  pe.ExportedSymbols.Forwards
  |> Map.iter (fun name (fwdBin, fwdFunc) ->
    let str = $"{name} (forwarded to {fwdBin}.{fwdFunc})"
    printsr [| ""; str |])
  printDoubleHorizontalRule ()
  printsn ""

let dirEntToString (dirent: DirectoryEntry) =
  let rva = HexString.ofInt32 dirent.RelativeVirtualAddress
  let size = String.wrapParen (HexString.ofInt32 dirent.Size)
  rva + " " + size

let dumpExistingOptionalHeader (hdr: PEHeader) (pe: PEBinFile) =
  let magicValue = HexString.ofUInt64 (uint64 hdr.Magic)
  let magicString = String.wrapParen <| hdr.Magic.ToString()
  let majorLinkerVer = hdr.MajorLinkerVersion.ToString()
  let minorLinkerVer = hdr.MinorLinkerVersion.ToString()
  let sizeOfInitData = HexString.ofUInt64 (uint64 hdr.SizeOfInitializedData)
  let sizeOfUninitData = HexString.ofUInt64 (uint64 hdr.SizeOfUninitializedData)
  let imgBase = hdr.ImageBase
  let sizeOfImage = uint64 hdr.SizeOfImage
  let entryPoint = HexString.ofUInt64 (imgBase + uint64 hdr.AddressOfEntryPoint)
  let startImage = HexString.ofUInt64 imgBase
  let endImage = HexString.ofUInt64 (imgBase + sizeOfImage - uint64 1)
  let imgRange = String.wrapParen (startImage + " to " + endImage)
  let majorOSVer = hdr.MajorOperatingSystemVersion.ToString()
  let minorOSVer = hdr.MinorOperatingSystemVersion.ToString()
  let majorImgVer = hdr.MajorImageVersion.ToString()
  let minorImgVer = hdr.MinorImageVersion.ToString()
  let majorSubsysVer = hdr.MajorSubsystemVersion.ToString()
  let minorSubsysVer = hdr.MinorSubsystemVersion.ToString()
  let subSysHex = HexString.ofUInt64 (uint64 hdr.Subsystem)
  let subSysStr = String.wrapParen (hdr.Subsystem.ToString())
  let charsHex = HexString.ofUInt64 (uint64 hdr.DllCharacteristics)
  let stackReserve = HexString.ofUInt64 hdr.SizeOfStackReserve
  let stackCommit = HexString.ofUInt64 hdr.SizeOfStackCommit
  let heapReserve = HexString.ofUInt64 hdr.SizeOfHeapReserve
  let heapCommit = HexString.ofUInt64 hdr.SizeOfHeapCommit
  let exportDir = dirEntToString hdr.ExportTableDirectory
  let importDir = dirEntToString hdr.ImportTableDirectory
  let resourceDir = dirEntToString hdr.ResourceTableDirectory
  let exceptionDir = dirEntToString hdr.ExceptionTableDirectory
  let certificateDir = dirEntToString hdr.CertificateTableDirectory
  let baseRelocDir = dirEntToString hdr.BaseRelocationTableDirectory
  let debugDir = dirEntToString hdr.DebugTableDirectory
  let architectureDir = dirEntToString hdr.CopyrightTableDirectory
  let globalPtrDir = dirEntToString hdr.GlobalPointerTableDirectory
  let threadLoStorDir = dirEntToString hdr.ThreadLocalStorageTableDirectory
  let loadConfigDir = dirEntToString hdr.ThreadLocalStorageTableDirectory
  let boundImpDir = dirEntToString hdr.BoundImportTableDirectory
  let importAddrDir = dirEntToString hdr.ImportAddressTableDirectory
  let delayImpDir = dirEntToString hdr.DelayImportTableDirectory
  let comDescDir = dirEntToString hdr.CorHeaderTableDirectory
  setTableColumnFormats [| RightAligned 45; LeftAligned 40 |]
  printsr [| "Magic:"; magicValue + " " + magicString |]
  printsr [| "Linker version:"; majorLinkerVer + "." + minorLinkerVer |]
  printsr [| "Size of code:"; HexString.ofUInt64 (uint64 hdr.SizeOfCode) |]
  printsr [| "Size of initialized data:"; sizeOfInitData |]
  printsr [| "Size of uninitialized data:"; sizeOfUninitData |]
  printsr [| "Entry point:"; entryPoint |]
  printsr [| "Base of code:"; HexString.ofUInt64 (uint64 hdr.BaseOfCode) |]
  printsr [| "Image base:"; HexString.ofUInt64 imgBase + " " + imgRange |]
  printsr [| "Section alignment:"; HexString.ofInt32 hdr.SectionAlignment |]
  printsr [| "File Alignment:"; HexString.ofInt32 hdr.FileAlignment |]
  printsr [| "Operating system version:"; majorOSVer + "." + minorOSVer |]
  printsr [| "Image version:"; majorImgVer + "." + minorImgVer |]
  printsr [| "Subsystem version:"; majorSubsysVer + "." + minorSubsysVer |]
  printsr [| "Size of image:"; HexString.ofUInt64 sizeOfImage |]
  printsr [| "Size of headers:"; HexString.ofInt32 hdr.SizeOfHeaders |]
  printsr [| "Checksum:"; HexString.ofUInt64 (uint64 hdr.CheckSum) |]
  printsr [| "Subsystem:"; subSysHex + " " + subSysStr |]
  printsr [| "DLL characteristics:"; charsHex |]
  for ch in enumerateFlags hdr.DllCharacteristics do
    printsr [| ""; String.ofEnum ch |]
  printsr [| "Size of stack reserve:"; stackReserve |]
  printsr [| "Size of stack commit:"; stackCommit |]
  printsr [| "Size of heap reserve:"; heapReserve |]
  printsr [| "Size of heap commit:"; heapCommit |]
  printsr [| "Number of directories:"; hdr.NumberOfRvaAndSizes.ToString() |]
  printsr [| "RVA (size) of Export Directory:"; exportDir |]
  printsr [| "RVA (size) of Import Directory:"; importDir |]
  printsr [| "RVA (size) of Resource Directory:"; resourceDir |]
  printsr [| "RVA (size) of Exception Directory:"; exceptionDir |]
  printsr [| "RVA (size) of Certificate Directory:"; certificateDir |]
  printsr [| "RVA (size) of Base Relocation Directory:"; baseRelocDir |]
  printsr [| "RVA (size) of Debug Directory:"; debugDir |]
  printsr [| "RVA (size) of Architecture Directory:"; architectureDir |]
  printsr [| "RVA (size) of Global Pointer Directory:"; globalPtrDir |]
  printsr [| "RVA (size) of Thread Storage Directory:"; threadLoStorDir |]
  printsr [| "RVA (size) of Load Configuration Directory:"; loadConfigDir |]
  printsr [| "RVA (size) of Bound Import Directory:"; boundImpDir |]
  printsr [| "RVA (size) of Import Address Table Directory:"; importAddrDir |]
  printsr [| "RVA (size) of Delay Import Table Directory:"; delayImpDir |]
  printsr [| "RVA (size) of COM Descriptor Directory:"; comDescDir |]
  printsn ""

let dumpOptionalHeader _ (pe: PEBinFile) =
  let hdr = pe.PEHeaders.PEHeader
  if isNull hdr then
    printsn (normalizeEmpty "")
    printsn ""
  else
    dumpExistingOptionalHeader hdr pe

let dumpCLRHeader _ (pe: PEBinFile) =
  let hdr = pe.PEHeaders.CorHeader
  setTableColumnFormats [| RightAligned 52; LeftAligned 40 |]
  if isNull hdr then
    printsn (normalizeEmpty "")
    printsn ""
  else
    let majorRuntimeVer = hdr.MajorRuntimeVersion.ToString()
    let minorRuntimeVer = hdr.MinorRuntimeVersion.ToString()
    let metaDataDir = dirEntToString hdr.MetadataDirectory
    let resourcesDir = dirEntToString hdr.ResourcesDirectory
    let strongDir = dirEntToString hdr.StrongNameSignatureDirectory
    let codeMgrTblDir = dirEntToString hdr.CodeManagerTableDirectory
    let vTableFixups = dirEntToString hdr.VtableFixupsDirectory
    let eatJmps = dirEntToString hdr.ExportAddressTableJumpsDirectory
    let managedDir = dirEntToString hdr.ManagedNativeHeaderDirectory
    printsr [| "Runtime version:"; majorRuntimeVer + "." + minorRuntimeVer |]
    printsr [| "RVA (size) of Meta Data Directory:"; metaDataDir |]
    printsr [| "Flags:"; HexString.ofUInt64 (uint64 hdr.Flags) |]
    for ch in enumerateFlags hdr.Flags do
      printsr [| ""; String.ofEnum ch |]
    printsr [| "RVA (size) of Resources Directory:"; resourcesDir |]
    printsr [| "RVA (size) of Strong Name Signature Directory:"; strongDir |]
    printsr [| "RVA (size) of Code Manager Table Directory:"; codeMgrTblDir |]
    printsr [| "RVA (size) of VTable Fixups Directory:"; vTableFixups |]
    printsr [| "RVA (size) of Export Address Table Jumps Directory:"; eatJmps |]
    printsr [| "RVA (size) of Managed Native Header Directory:"; managedDir |]
    printsn ""

let dumpDependencies _ (file: IBinFile) =
  file.GetLinkageTableEntries()
  |> Array.map (fun e -> e.LibraryName)
  |> Set.ofArray
  |> Set.iter (fun s -> printsn $"- {s}")
  printsn ""

let dumpExceptionTable _ _ =
  Terminator.futureFeature ()
