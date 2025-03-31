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

module internal B2R2.FrontEnd.BinFile.PE.Parser

open System
open System.Reflection.PortableExecutable
open B2R2
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.FileHelper
open B2R2.FrontEnd.BinFile.PE.Helper

/// This is equivalent to GetContainingSectionIndex function except that we are
/// using our own section header array here. This should be used instead of
/// GetContainingSectionIndex when analyzing binaries that contain sections
/// whose file size is less than its memory size, e.g., COFF binaries.
let findMappedSectionIndex (secs: SectionHeader []) rva =
  secs
  |> Array.tryFindIndex (fun s ->
    s.VirtualAddress <= rva && rva < s.VirtualAddress + s.SizeOfRawData)
  |> Option.defaultValue -1

let findSectionIndex (hdrs: PEHeaders) secs rva =
  let idx = hdrs.GetContainingSectionIndex rva
  if idx < 0 then findMappedSectionIndex secs rva
  else idx

let getRawOffset secs rva =
  let idx = findMappedSectionIndex secs rva
  let sHdr = secs[idx]
  rva + sHdr.PointerToRawData - sHdr.VirtualAddress

let readStr secs (bytes: byte[]) rva =
  if rva = 0 then ""
  else readCString (ReadOnlySpan bytes) (getRawOffset secs rva)

let isNULLImportDir tbl =
  tbl.ImportLookupTableRVA = 0
  && tbl.ForwarderChain = 0
  && tbl.ImportDLLName = ""
  && tbl.ImportAddressTableRVA = 0

let decodeForwardInfo (str: string) =
  let strInfo = str.Split('.')
  let dllName, funcName = strInfo[0], strInfo[1]
  (dllName, funcName)

let readExportDirectoryTableEntry bytes (reader: IBinReader) tbl secs =
  { ExportDLLName = readStr secs bytes (reader.ReadInt32 (span=tbl, offset=12))
    OrdinalBase = reader.ReadInt32 (tbl, 16)
    AddressTableEntries = reader.ReadInt32 (tbl, 20)
    NumNamePointers = reader.ReadInt32 (tbl, 24)
    ExportAddressTableRVA = reader.ReadInt32 (tbl, 28)
    NamePointerRVA = reader.ReadInt32 (tbl, 32)
    OrdinalTableRVA = reader.ReadInt32 (tbl, 36) }

let inline getEATEntry (lowerBound, upperBound) rva =
  if rva < lowerBound || rva > upperBound then ExportRVA rva
  else ForwarderRVA rva

let parseEAT bytes (reader: IBinReader) secs range edt =
  match edt.ExportAddressTableRVA with
  | 0 -> [||]
  | rva ->
    let offset = getRawOffset secs rva
    let span = ReadOnlySpan (bytes, offset, edt.AddressTableEntries * 4)
    let addrTbl = Array.zeroCreate edt.AddressTableEntries
    for i = 0 to edt.AddressTableEntries - 1 do
      let rva = reader.ReadInt32 (span, i * 4)
      addrTbl[i] <- getEATEntry range rva
    addrTbl

/// Parse Export Name Pointer Table (ENPT).
let parseENPT (bytes: byte[]) (reader: IBinReader) secs edt =
  let rec loop acc cnt pos1 pos2 =
    if cnt = 0 then acc
    else
      let rva = reader.ReadInt32 (bytes, pos1)
      let str = readStr secs bytes rva
      let ord = reader.ReadInt16 (bytes, pos2)
      loop ((str, ord) :: acc) (cnt - 1) (pos1 + 4) (pos2 + 2)
  if edt.NamePointerRVA = 0 then []
  else
    let offset1 = edt.NamePointerRVA |> getRawOffset secs
    let offset2 = edt.OrdinalTableRVA |> getRawOffset secs
    loop [] edt.NumNamePointers offset1 offset2

/// Decide the name of an exported address. The address may have been exported
/// only with ordinal, and does not have a corresponding name in export name
/// pointer table. In such case, consider its name as "#<Ordinal>".
let private decideNameWithTable nameTbl ordBase idx =
  match List.tryFind (fun (_, ord) -> int16 idx = ord) nameTbl with
  | None -> sprintf "#%d" (int16 idx + ordBase) // Exported with an ordinal.
  | Some (name, _) -> name // ENTP has a corresponding name for this entry.

let buildExportTable bytes reader baseAddr secs range edt =
  let addrTbl = parseEAT bytes reader secs range edt
  let nameTbl = parseENPT bytes reader secs edt
  let ordinalBase = int16 edt.OrdinalBase
  let folder (expMap, forwMap) idx = function
    | ExportRVA rva ->
      let addr = addrFromRVA baseAddr rva
      let name = decideNameWithTable nameTbl ordinalBase idx
      let expMap =
        if not (Map.containsKey addr expMap) then Map.add addr [name] expMap
        else Map.add addr (name :: Map.find addr expMap) expMap
      expMap, forwMap
    | ForwarderRVA rva ->
      let name = decideNameWithTable nameTbl ordinalBase idx
      let forwardStr = readStr secs bytes rva
      let forwardInfo = decodeForwardInfo forwardStr
      let forwMap = Map.add name forwardInfo forwMap
      expMap, forwMap
  Array.foldi folder (Map.empty, Map.empty) addrTbl |> fst

let parseExports baseAddr bytes reader (headers: PEHeaders) secs =
  match headers.PEHeader.ExportTableDirectory.RelativeVirtualAddress with
  | 0 -> Map.empty, Map.empty
  | rva ->
    let size = headers.PEHeader.ExportTableDirectory.Size
    let range = (rva, rva + size)
    let offset = getRawOffset secs rva
    let tbl = ReadOnlySpan (bytes, offset, size)
    readExportDirectoryTableEntry bytes reader tbl secs
    |> buildExportTable bytes reader baseAddr secs range

let readIDTEntry (bs: byte[]) (reader: IBinReader) secs pos =
  { ImportLookupTableRVA = reader.ReadInt32 (bs, pos)
    ForwarderChain = reader.ReadInt32 (bs, pos + 8)
    ImportDLLName = reader.ReadInt32 (bs, pos + 12) |> readStr secs bs
    ImportAddressTableRVA = reader.ReadInt32 (bs, pos + 16)
    DelayLoad = false }

let readDelayIDTEntry (bs: byte[]) (reader: IBinReader) secs pos =
  { ImportLookupTableRVA = reader.ReadInt32 (bs, pos + 16)
    ForwarderChain = 0
    ImportDLLName = reader.ReadInt32 (bs, pos + 4) |> readStr secs bs
    ImportAddressTableRVA = reader.ReadInt32 (bs, pos + 12)
    DelayLoad = true }

let parseImportDirectoryTblAux bytes reader secs entrySize rva readFn =
  if rva = 0 then [||]
  else
    let rec loop acc offset =
      let tbl = readFn bytes reader secs offset
      if isNULLImportDir tbl then acc
      else loop (tbl :: acc) (offset + entrySize)
    getRawOffset secs rva |> loop [] |> List.rev |> List.toArray

let parseImportDirectoryTable bytes reader (headers: PEHeaders) secs =
  let rva = headers.PEHeader.ImportTableDirectory.RelativeVirtualAddress
  parseImportDirectoryTblAux bytes reader secs 20 rva readIDTEntry

let parseDelayImportDirectoryTable bytes reader (headers: PEHeaders) secs =
  let rva = headers.PEHeader.DelayImportTableDirectory.RelativeVirtualAddress
  parseImportDirectoryTblAux bytes reader secs 32 rva readDelayIDTEntry

let parseILTEntry (bytes: byte[]) (reader: IBinReader) secs idt mask rva =
  let dllname = idt.ImportDLLName
  if rva &&& mask <> 0UL then
    ImportByOrdinal (uint16 rva |> int16, dllname)
  else
    let rva = 0x7fffffffUL &&& rva |> int
    let hint = reader.ReadInt16 (bytes, getRawOffset secs rva)
    let funname = readStr secs bytes (rva + 2)
    ImportByName (hint, funname, dllname)

let computeRVAMaskForILT wordSize =
  if wordSize = WordSize.Bit32 then 0x80000000UL
  else 0x8000000000000000UL

let parseILT (bytes: byte[]) (reader: IBinReader) secs wordSize map idt =
  let skip = if wordSize = WordSize.Bit32 then 4 else 8
  let mask = computeRVAMaskForILT wordSize
  let rec loop map rvaOffset pos =
    let rva = readUIntOfType (ReadOnlySpan bytes) reader wordSize pos
    if rva = 0UL then map
    else
      let entry = parseILTEntry bytes reader secs idt mask rva
      let map = Map.add (idt.ImportAddressTableRVA + rvaOffset) entry map
      loop map (rvaOffset + skip) (pos + skip)
  if idt.ImportLookupTableRVA <> 0 then idt.ImportLookupTableRVA
  else idt.ImportAddressTableRVA
  |> getRawOffset secs
  |> loop map 0

let parseImports bytes reader (headers: PEHeaders) secs wordSize =
  let mainImportTbl = parseImportDirectoryTable bytes reader headers secs
  let delayImportTbl = parseDelayImportDirectoryTable bytes reader headers secs
  Array.append mainImportTbl delayImportTbl
  |> Array.toList
  |> List.fold (parseILT bytes reader secs wordSize) Map.empty

let buildRelocBlock (bytes: byte[]) (reader: IBinReader) headerOffset =
  let blockSize = reader.ReadInt32 (bytes, headerOffset + 4)
  let upperBound = headerOffset + blockSize
  let rec parseBlock offset entries =
    if offset < upperBound then
      let buffer = reader.ReadUInt16 (bytes, offset)
      { Type = buffer >>> 12 |> int32 |> LanguagePrimitives.EnumOfValue;
        Offset = buffer &&& 0xFFFus }::entries
      |> parseBlock (offset + 2)
    else
      entries |> List.toArray
  { PageRVA = reader.ReadUInt32 (bytes, headerOffset)
    BlockSize = blockSize
    Entries = parseBlock (headerOffset + 8) List.empty }

let parseRelocation bytes (reader: IBinReader) (headers: PEHeaders) secs =
  let peHdr = headers.PEHeader
  match peHdr.BaseRelocationTableDirectory.RelativeVirtualAddress with
  | 0 -> List.empty
  | rva ->
    let hdrOffset = getRawOffset secs rva
    let upperBound = hdrOffset + peHdr.BaseRelocationTableDirectory.Size
    let rec parseRelocDirectory offset blks =
      if offset < upperBound then
        let relocBlk = buildRelocBlock bytes reader offset
        parseRelocDirectory (offset + relocBlk.BlockSize) (relocBlk :: blks)
      else blks
    parseRelocDirectory hdrOffset List.empty

let magicToWordSize = function
  | PEMagic.PE32 -> WordSize.Bit32
  | PEMagic.PE32Plus -> WordSize.Bit64
  | _ -> raise InvalidWordSizeException

let parsePDB reader (pdbBytes: byte[]) =
  let span = ReadOnlySpan pdbBytes
  if PDB.isPDBHeader span reader then ()
  else raise InvalidFileFormatException
  PDB.parse span reader

let getPDBSymbols reader (execpath: string) = function
  | [||] ->
    let pdbPath = IO.Path.ChangeExtension (execpath, "pdb")
    if IO.File.Exists pdbPath then
      IO.File.ReadAllBytes pdbPath |> parsePDB reader
    else []
  | rawpdb -> parsePDB reader rawpdb

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
    addInvalidRange set saddr myaddr, n) (IntervalSet.empty, 0UL)
  |> addLastInvalidRange wordSize

let computeInvalidAddrRanges wordSize baseAddr secs =
  invRanges wordSize baseAddr secs (fun a s ->
    a + (uint64 <| getVirtualSectionSize s))

let computeNotInFileRanges wordSize baseAddr secs =
  invRanges wordSize baseAddr secs (fun a s -> a + uint64 s.SizeOfRawData)

let execRanges baseAddr secs =
  secs
  |> Array.filter (fun (s: SectionHeader) ->
    let perm: Permission = getSecPermission s.SectionCharacteristics
    perm &&& Permission.Executable = Permission.Executable)
  |> Array.fold (fun set s ->
    let saddr = baseAddr + uint64 s.VirtualAddress
    let eaddr = saddr + (uint64 <| getVirtualSectionSize s)
    IntervalSet.add (AddrRange (saddr, eaddr - 1UL)) set
    ) IntervalSet.empty

let parseCoff baseAddrOpt bytes reader (hdrs: PEHeaders) =
  let coff = hdrs.CoffHeader
  let baseAddr = defaultArg baseAddrOpt 0UL
  let wordSize = Coff.getWordSize coff.Machine
  let secs = hdrs.SectionHeaders |> Seq.toArray
  let idx = secs |> Array.findIndex (fun s -> s.Name.StartsWith ".text")
  let findSectionIdxFromRVA = fun _ -> idx
  { PEHeaders = hdrs
    BaseAddr = baseAddr
    SectionHeaders = secs
    ImportMap= Map.empty
    ExportMap = Map.empty
    ForwardMap = Map.empty
    RelocBlocks = []
    WordSize = wordSize
    SymbolInfo = Coff.getSymbols bytes reader coff
    InvalidAddrRanges = IntervalSet.empty
    NotInFileRanges = IntervalSet.empty
    ExecutableRanges = execRanges baseAddr secs
    FindSectionIdxFromRVA = findSectionIdxFromRVA
    BinReader = reader }

let parseImage execpath rawpdb baseAddr bytes reader (hdrs: PEHeaders) =
  let wordSize = magicToWordSize hdrs.PEHeader.Magic
  let baseAddr = defaultArg baseAddr hdrs.PEHeader.ImageBase
  let secs = hdrs.SectionHeaders |> Seq.toArray
  let exportMap, forwardMap = parseExports baseAddr bytes reader hdrs secs
  { PEHeaders = hdrs
    BaseAddr = baseAddr
    SectionHeaders = secs
    ImportMap = parseImports bytes reader hdrs secs wordSize
    ExportMap = exportMap
    ForwardMap = forwardMap
    RelocBlocks = parseRelocation bytes reader hdrs secs
    WordSize = wordSize
    SymbolInfo =
      getPDBSymbols reader execpath rawpdb |> buildPDBInfo baseAddr secs
    InvalidAddrRanges = computeInvalidAddrRanges wordSize baseAddr secs
    NotInFileRanges = computeNotInFileRanges wordSize baseAddr secs
    ExecutableRanges = execRanges baseAddr secs
    FindSectionIdxFromRVA = findSectionIndex hdrs secs
    BinReader = reader }

let parsePE execpath baseAddrOpt rawpdb bytes reader (peReader: PEReader) =
  let hdrs = peReader.PEHeaders
  if hdrs.IsCoffOnly then parseCoff baseAddrOpt bytes reader hdrs
  else parseImage execpath rawpdb baseAddrOpt bytes reader hdrs

let parse execpath (bytes: byte[]) baseAddrOpt rawpdb =
  let reader = BinReader.Init Endian.Little
  use stream = new IO.MemoryStream (bytes)
  use peReader = new PEReader (stream, PEStreamOptions.Default)
  parsePE execpath baseAddrOpt rawpdb bytes reader peReader
