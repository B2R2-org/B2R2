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

module internal B2R2.BinFile.PE.Parser

open System
open System.Reflection.PortableExecutable
open B2R2
open B2R2.BinFile
open B2R2.BinFile.PE.Helper

/// This is equivalent to GetContainingSectionIndex function except that we are
/// using our own section header array here. This should be used instead of
/// GetContainingSectionIndex as we sometimes consider only a subset of the
/// sections in a file, e.g., when analyzing COFF binaries.
let findSectionIndex (secs: SectionHeader []) rva =
  secs
  |> Array.tryFindIndex (fun s ->
    s.VirtualAddress <= rva && rva < s.VirtualAddress + s.SizeOfRawData)
  |> Option.defaultValue -1

let getRawOffset secs rva =
  let idx = findSectionIndex secs rva
  let sHdr = secs.[idx]
  rva + sHdr.PointerToRawData - sHdr.VirtualAddress

let readStr secs (binReader: BinReader) rva =
  if rva = 0 then ""
  else getRawOffset secs rva |> FileHelper.peekCString binReader

let isNULLImportDir tbl =
  tbl.ImportLookupTableRVA = 0
  && tbl.ForwarderChain = 0
  && tbl.ImportDLLName = ""
  && tbl.ImportAddressTableRVA = 0

let readIDTEntry (binReader: BinReader) secs pos =
  { ImportLookupTableRVA = binReader.PeekInt32 pos
    ForwarderChain = binReader.PeekInt32 (pos + 8)
    ImportDLLName = binReader.PeekInt32 (pos + 12) |> readStr secs binReader
    ImportAddressTableRVA = binReader.PeekInt32 (pos + 16)
    DelayLoad = false }

let readDelayIDTEntry (binReader: BinReader) secs pos =
  { ImportLookupTableRVA = binReader.PeekInt32 (pos + 16)
    ForwarderChain = 0
    ImportDLLName = binReader.PeekInt32 (pos + 4) |> readStr secs binReader
    ImportAddressTableRVA = binReader.PeekInt32 (pos + 12)
    DelayLoad = true }

let parseImportDirectoryTableAux binReader secs readFn nextPos = function
  | 0 -> [||]
  | rva ->
    let rec loop acc pos =
      let tbl = readFn binReader secs pos
      if isNULLImportDir tbl then acc else loop (tbl :: acc) (nextPos pos)
    getRawOffset secs rva |> loop [] |> List.rev |> List.toArray

let parseImportDirectoryTable binReader (headers: PEHeaders) secs =
  let nextPos pos = pos + 20
  headers.PEHeader.ImportTableDirectory.RelativeVirtualAddress
  |> parseImportDirectoryTableAux binReader secs readIDTEntry nextPos

let parseDelayImportDirectoryTable binReader (headers: PEHeaders) secs =
  let nextPos pos = pos + 32
  headers.PEHeader.DelayImportTableDirectory.RelativeVirtualAddress
  |> parseImportDirectoryTableAux binReader secs readDelayIDTEntry nextPos

let parseILTEntry (binReader: BinReader) secs idt mask rva =
  let dllname = idt.ImportDLLName
  if rva &&& mask <> 0UL then
    ImportByOrdinal (uint16 rva |> int16, dllname)
  else
    let rva = 0x7fffffffUL &&& rva |> int
    let hint = getRawOffset secs rva |> binReader.PeekInt16
    let funname = readStr secs binReader (rva + 2)
    ImportByName (hint, funname, dllname)

let computeRVAMaskForILT wordSize =
  if wordSize = WordSize.Bit32 then 0x80000000UL
  else 0x8000000000000000UL

let parseILT binReader secs wordSize map idt =
  let skip = if wordSize = WordSize.Bit32 then 4 else 8
  let mask = computeRVAMaskForILT wordSize
  let rec loop map rvaOffset pos =
    let rva = FileHelper.peekUIntOfType binReader wordSize pos
    if rva = 0UL then map
    else
      let entry = parseILTEntry binReader secs idt mask rva
      let map = Map.add (idt.ImportAddressTableRVA + rvaOffset) entry map
      loop map (rvaOffset + skip) (pos + skip)
  if idt.ImportLookupTableRVA <> 0 then idt.ImportLookupTableRVA
  else idt.ImportAddressTableRVA
  |> getRawOffset secs
  |> loop map 0

let parseImports (binReader: BinReader) (headers: PEHeaders) secs wordSize =
  let mainImportTable = parseImportDirectoryTable binReader headers secs
  let delayImportTable = parseDelayImportDirectoryTable binReader headers secs
  Array.append mainImportTable delayImportTable
  |> Array.toList
  |> List.fold (parseILT binReader secs wordSize) Map.empty

let readExportDirectoryTableEntry (binReader: BinReader) secs pos =
  { ExportDLLName = binReader.PeekInt32 (pos + 12) |> readStr secs binReader
    OrdinalBase = binReader.PeekInt32 (pos + 16)
    AddressTableEntries = binReader.PeekInt32 (pos + 20)
    NumNamePointers = binReader.PeekInt32 (pos + 24)
    ExportAddressTableRVA = binReader.PeekInt32 (pos + 28)
    NamePointerRVA = binReader.PeekInt32 (pos + 32)
    OrdinalTableRVA = binReader.PeekInt32 (pos + 36) }

let parseEAT (binReader: BinReader) secs range edt =
  let lowerbound, upperbound = range
  let getEntry rva =
    if rva < lowerbound || rva > upperbound then ExportRVA rva
    else ForwarderRVA rva
  let rec loop acc cnt pos =
    if cnt = 0 then List.rev acc |> List.toArray
    else let rva = binReader.PeekInt32 (pos)
         loop (getEntry rva :: acc) (cnt - 1) (pos + 4)
  match edt.ExportAddressTableRVA with
  | 0 -> [||]
  | rva -> getRawOffset secs rva |> loop [] edt.AddressTableEntries

/// Parse Export Name Pointer Table (ENPT).
let parseENPT (binReader: BinReader) secs edt =
  let rec loop acc cnt pos1 pos2 =
    if cnt = 0 then acc
    else let str = binReader.PeekInt32 (pos1) |> readStr secs binReader
         let ord = binReader.PeekInt16 (pos2)
         loop ((str, ord) :: acc) (cnt - 1) (pos1 + 4) (pos2 + 2)
  if edt.NamePointerRVA = 0 then []
  else
    let offset1 = edt.NamePointerRVA |> getRawOffset secs
    let offset2 = edt.OrdinalTableRVA |> getRawOffset secs
    loop [] edt.NumNamePointers offset1 offset2

let buildExportTable binReader (headers: PEHeaders) secs range edt =
  let addrtbl = parseEAT binReader secs range edt
  let folder map (name, ord) =
    match addrtbl.[int ord] with
    | ExportRVA rva ->
      let addr = addrFromRVA headers.PEHeader.ImageBase rva
      Map.add addr name map
    | _ -> map
  parseENPT binReader secs edt
  |> List.fold folder Map.empty

let parseExports binReader (headers: PEHeaders) secs =
  match headers.PEHeader.ExportTableDirectory.RelativeVirtualAddress with
  | 0 -> Map.empty
  | rva ->
    let idx = findSectionIndex secs rva
    let size = headers.PEHeader.ExportTableDirectory.Size
    let range = (rva, rva + size)
    getRawOffset secs rva
    |> readExportDirectoryTableEntry binReader secs
    |> buildExportTable binReader headers secs range

let buildRelocBlock (binReader: BinReader) headerOffset =
  let blockSize = binReader.PeekInt32 (headerOffset + 4)
  let upperBound = headerOffset + blockSize
  let rec parseBlock offset entries =
    if offset < upperBound then
      let buffer = binReader.PeekUInt16(offset)
      { Type = buffer >>> 12 |> int32 |> LanguagePrimitives.EnumOfValue;
        Offset = buffer &&& 0xFFFus }::entries
      |> parseBlock (offset + 2)
    else
      entries |> List.toArray
  { PageRVA = binReader.PeekUInt32 headerOffset
    BlockSize = blockSize
    Entries = parseBlock (headerOffset + 8) List.empty }

let parseRelocation (binReader: BinReader) (headers: PEHeaders) secs =
  let peHdr = headers.PEHeader
  match peHdr.BaseRelocationTableDirectory.RelativeVirtualAddress with
  | 0 -> List.empty
  | rva ->
    let hdrOffset = getRawOffset secs rva
    let upperBound = hdrOffset + peHdr.BaseRelocationTableDirectory.Size
    let rec parseRelocDirectory offset blks =
      if offset < upperBound then
        let relocBlk = buildRelocBlock binReader offset
        parseRelocDirectory (offset + relocBlk.BlockSize) (relocBlk :: blks)
      else blks
    parseRelocDirectory hdrOffset List.empty

let magicToWordSize = function
  | PEMagic.PE32 -> WordSize.Bit32
  | PEMagic.PE32Plus -> WordSize.Bit64
  | _ -> raise InvalidWordSizeException

let parsePDB pdbBytes =
  let reader = BinReader.Init (pdbBytes)
  if PDB.isPDBHeader reader 0 then ()
  else raise FileFormatMismatchException
  PDB.parse reader 0

let getPDBSymbols (execpath: string) = function
  | [||] ->
    let pdbPath = IO.Path.ChangeExtension (execpath, "pdb")
    if IO.File.Exists pdbPath then IO.File.ReadAllBytes pdbPath |> parsePDB
    else []
  | rawpdb -> parsePDB rawpdb

let updatePDBInfo baseAddr secs mAddr mName lst (sym: PESymbol) =
  let secNum = int sym.Segment - 1
  match Array.tryItem secNum (secs: SectionHeader []) with
  | Some sec ->
    let addr = baseAddr + uint64 sec.VirtualAddress + uint64 sym.Address
    let sym = { sym with Address = addr }
    struct (Map.add addr sym mAddr, Map.add sym.Name sym mName, sym :: lst)
  | None -> struct (mAddr, mName, lst)

let buildPDBInfo baseAddr secs symbs =
  let rec folder mAddr mName lst = function
    | sym :: rest ->
      let struct (mAddr, mName, lst) =
        updatePDBInfo baseAddr secs mAddr mName lst sym
      folder mAddr mName lst rest
    | [] ->
      { SymbolByAddr = mAddr
        SymbolByName = mName
        SymbolArray = List.rev lst |> List.toArray }
  symbs
  |> folder Map.empty Map.empty []

let invRanges wordSize baseAddr secs getNextStartAddr =
  secs
  |> Array.sortBy (fun (s: SectionHeader) -> s.VirtualAddress)
  |> Array.fold (fun (set, saddr) s ->
    let myaddr = uint64 s.VirtualAddress + baseAddr
    let n = getNextStartAddr myaddr s
    FileHelper.addInvRange set saddr myaddr, n) (IntervalSet.empty, 0UL)
  |> FileHelper.addLastInvRange wordSize

let computeInvalidAddrRanges wordSize baseAddr secs =
  invRanges wordSize baseAddr secs (fun a s ->
    a + (uint64 <| getVirtualSectionSize s))

let computeNotInFileRanges wordSize baseAddr secs =
  invRanges wordSize baseAddr secs (fun a s -> a + uint64 s.SizeOfRawData)

let parseImage execpath rawpdb baseAddr binReader (hdrs: PEHeaders) =
  let wordSize = magicToWordSize hdrs.PEHeader.Magic
  let baseAddr = hdrs.PEHeader.ImageBase + baseAddr
  let secs = hdrs.SectionHeaders |> Seq.toArray
  { PEHeaders = hdrs
    BaseAddr = baseAddr
    SectionHeaders = secs
    ImportMap= parseImports binReader hdrs secs wordSize
    ExportMap = parseExports binReader hdrs secs
    RelocBlocks = parseRelocation binReader hdrs secs
    WordSize = wordSize
    SymbolInfo = getPDBSymbols execpath rawpdb |> buildPDBInfo baseAddr secs
    InvalidAddrRanges = computeInvalidAddrRanges wordSize baseAddr secs
    NotInFileRanges = computeNotInFileRanges wordSize baseAddr secs
    FindSectionIdxFromRVA = findSectionIndex secs
    BinReader = binReader }

let parseCoff baseAddr binReader (hdrs: PEHeaders) =
  let coff = hdrs.CoffHeader
  let wordSize = Coff.getWordSize coff.Machine
  let secs = hdrs.SectionHeaders |> Seq.toArray
  let idx = secs |> Array.findIndex (fun s -> s.Name.StartsWith ".text")
  let findSectionIdxFromRVA = fun _ -> idx
  { PEHeaders = hdrs
    BaseAddr = baseAddr
    SectionHeaders = secs
    ImportMap= Map.empty
    ExportMap = Map.empty
    RelocBlocks = []
    WordSize = wordSize
    SymbolInfo = Coff.getSymbols binReader coff
    InvalidAddrRanges = IntervalSet.empty
    NotInFileRanges = IntervalSet.empty
    FindSectionIdxFromRVA = findSectionIdxFromRVA
    BinReader = binReader }

let parsePE execpath baseAddr rawpdb binReader (peReader: PEReader) =
  let hdrs = peReader.PEHeaders
  if hdrs.IsCoffOnly then parseCoff baseAddr binReader hdrs
  else parseImage execpath rawpdb baseAddr binReader hdrs

let parse bytes execpath baseAddr rawpdb =
  let binReader = BinReader.Init (bytes)
  use stream = new IO.MemoryStream (bytes)
  use peReader = new PEReader (stream, PEStreamOptions.Default)
  parsePE execpath baseAddr rawpdb binReader peReader
