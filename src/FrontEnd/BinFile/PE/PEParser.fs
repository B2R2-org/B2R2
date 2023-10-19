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

let readStr secs (bs: byte[]) rva =
  if rva = 0 then ""
  else readCString (ReadOnlySpan bs) (getRawOffset secs rva)

let isNULLImportDir tbl =
  tbl.ImportLookupTableRVA = 0
  && tbl.ForwarderChain = 0
  && tbl.ImportDLLName = ""
  && tbl.ImportAddressTableRVA = 0

let decodeForwardInfo (str: string) =
  let strInfo = str.Split('.')
  let dllName, funcName = strInfo[0], strInfo[1]
  (dllName, funcName)

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

let parseImportDirectoryTableAux bytes reader secs readFn nextPos = function
  | 0 -> [||]
  | rva ->
    let rec loop acc pos =
      let tbl = readFn bytes reader secs pos
      if isNULLImportDir tbl then acc else loop (tbl :: acc) (nextPos pos)
    getRawOffset secs rva |> loop [] |> List.rev |> List.toArray

let parseImportDirectoryTable bytes reader (headers: PEHeaders) secs =
  let nextPos pos = pos + 20
  headers.PEHeader.ImportTableDirectory.RelativeVirtualAddress
  |> parseImportDirectoryTableAux bytes reader secs readIDTEntry nextPos

let parseDelayImportDirectoryTable bytes reader (headers: PEHeaders) secs =
  let nextPos pos = pos + 32
  headers.PEHeader.DelayImportTableDirectory.RelativeVirtualAddress
  |> parseImportDirectoryTableAux bytes reader secs readDelayIDTEntry nextPos

let parseILTEntry (bs: byte[]) (reader: IBinReader) secs idt mask rva =
  let dllname = idt.ImportDLLName
  if rva &&& mask <> 0UL then
    ImportByOrdinal (uint16 rva |> int16, dllname)
  else
    let rva = 0x7fffffffUL &&& rva |> int
    let hint = reader.ReadInt16 (bs, getRawOffset secs rva)
    let funname = readStr secs bs (rva + 2)
    ImportByName (hint, funname, dllname)

let computeRVAMaskForILT wordSize =
  if wordSize = WordSize.Bit32 then 0x80000000UL
  else 0x8000000000000000UL

let parseILT (bs: byte[]) reader secs wordSize map idt =
  let skip = if wordSize = WordSize.Bit32 then 4 else 8
  let mask = computeRVAMaskForILT wordSize
  let rec loop map rvaOffset pos =
    let rva = readUIntOfType (ReadOnlySpan bs) reader wordSize pos
    if rva = 0UL then map
    else
      let entry = parseILTEntry bs reader secs idt mask rva
      let map = Map.add (idt.ImportAddressTableRVA + rvaOffset) entry map
      loop map (rvaOffset + skip) (pos + skip)
  if idt.ImportLookupTableRVA <> 0 then idt.ImportLookupTableRVA
  else idt.ImportAddressTableRVA
  |> getRawOffset secs
  |> loop map 0

let parseImports bs reader (headers: PEHeaders) secs wordSize =
  let mainImportTable = parseImportDirectoryTable bs reader headers secs
  let delayImportTable = parseDelayImportDirectoryTable bs reader headers secs
  Array.append mainImportTable delayImportTable
  |> Array.toList
  |> List.fold (parseILT bs reader secs wordSize) Map.empty

let readExportDirectoryTableEntry (bs: byte[]) (reader: IBinReader) secs pos =
  { ExportDLLName = readStr secs bs (reader.ReadInt32 (bs, pos + 12))
    OrdinalBase = reader.ReadInt32 (bs, pos + 16)
    AddressTableEntries = reader.ReadInt32 (bs, pos + 20)
    NumNamePointers = reader.ReadInt32 (bs, pos + 24)
    ExportAddressTableRVA = reader.ReadInt32 (bs, pos + 28)
    NamePointerRVA = reader.ReadInt32 (bs, pos + 32)
    OrdinalTableRVA = reader.ReadInt32 (bs, pos + 36) }

let parseEAT (bs: byte[]) (reader: IBinReader) secs range edt =
  let lowerbound, upperbound = range
  let getEntry rva =
    if rva < lowerbound || rva > upperbound then ExportRVA rva
    else ForwarderRVA rva
  let rec loop acc cnt pos =
    if cnt = 0 then List.rev acc |> List.toArray
    else let rva = reader.ReadInt32 (bs, pos)
         loop (getEntry rva :: acc) (cnt - 1) (pos + 4)
  match edt.ExportAddressTableRVA with
  | 0 -> [||]
  | rva -> getRawOffset secs rva |> loop [] edt.AddressTableEntries

/// Parse Export Name Pointer Table (ENPT).
let parseENPT (bs: byte[]) (reader: IBinReader) secs edt =
  let rec loop acc cnt pos1 pos2 =
    if cnt = 0 then acc
    else let str = readStr secs bs (reader.ReadInt32 (bs, pos1))
         let ord = reader.ReadInt16 (bs, pos2)
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

let buildExportTable bs reader baseAddr secs range edt =
  let addrTbl = parseEAT bs reader secs range edt
  let nameTbl = parseENPT bs reader secs edt
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
      let forwardStr = readStr secs bs rva
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
    getRawOffset secs rva
    |> readExportDirectoryTableEntry bytes reader secs
    |> buildExportTable bytes reader baseAddr secs range

let buildRelocBlock (bs: byte[]) (reader: IBinReader) headerOffset =
  let blockSize = reader.ReadInt32 (bs, headerOffset + 4)
  let upperBound = headerOffset + blockSize
  let rec parseBlock offset entries =
    if offset < upperBound then
      let buffer = reader.ReadUInt16(bs, offset)
      { Type = buffer >>> 12 |> int32 |> LanguagePrimitives.EnumOfValue;
        Offset = buffer &&& 0xFFFus }::entries
      |> parseBlock (offset + 2)
    else
      entries |> List.toArray
  { PageRVA = reader.ReadUInt32 (bs, headerOffset)
    BlockSize = blockSize
    Entries = parseBlock (headerOffset + 8) List.empty }

let parseRelocation bs (reader: IBinReader) (headers: PEHeaders) secs =
  let peHdr = headers.PEHeader
  match peHdr.BaseRelocationTableDirectory.RelativeVirtualAddress with
  | 0 -> List.empty
  | rva ->
    let hdrOffset = getRawOffset secs rva
    let upperBound = hdrOffset + peHdr.BaseRelocationTableDirectory.Size
    let rec parseRelocDirectory offset blks =
      if offset < upperBound then
        let relocBlk = buildRelocBlock bs reader offset
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

let parseImage execpath rawpdb baseAddr bytes reader (hdrs: PEHeaders) =
  let wordSize = magicToWordSize hdrs.PEHeader.Magic
  let baseAddr = defaultArg baseAddr hdrs.PEHeader.ImageBase
  let secs = hdrs.SectionHeaders |> Seq.toArray
  let exportMap, forwardMap = parseExports baseAddr bytes reader hdrs secs
  { PEHeaders = hdrs
    BaseAddr = baseAddr
    SectionHeaders = secs
    ImportMap= parseImports bytes reader hdrs secs wordSize
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

let parseCoff baseAddr (bytes: byte[]) reader (hdrs: PEHeaders) =
  let coff = hdrs.CoffHeader
  let baseAddr = defaultArg baseAddr 0UL
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
    SymbolInfo = Coff.getSymbols (ReadOnlySpan bytes) reader coff
    InvalidAddrRanges = IntervalSet.empty
    NotInFileRanges = IntervalSet.empty
    ExecutableRanges = execRanges baseAddr secs
    FindSectionIdxFromRVA = findSectionIdxFromRVA
    BinReader = reader }

let parsePE execpath baseAddr rawpdb bytes reader (peReader: PEReader) =
  let hdrs = peReader.PEHeaders
  if hdrs.IsCoffOnly then parseCoff baseAddr bytes reader hdrs
  else parseImage execpath rawpdb baseAddr bytes reader hdrs

let parse (bytes: byte[]) execpath baseAddr rawpdb =
  let reader = BinReader.Init Endian.Little
  use stream = new IO.MemoryStream (bytes)
  use peReader = new PEReader (stream, PEStreamOptions.Default)
  parsePE execpath baseAddr rawpdb bytes reader peReader
