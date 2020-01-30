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
open B2R2
open B2R2.BinFile
open B2R2.BinFile.PE.Helper
open System.Reflection.PortableExecutable

let getRawOffset (headers: PEHeaders) rva =
  let idx = findSectionIndex headers rva
  let sHdr = headers.SectionHeaders.[idx]
  rva + sHdr.PointerToRawData - sHdr.VirtualAddress

let readStr headers (binReader: BinReader) rva =
  let rec loop acc pos =
    let byte = binReader.PeekByte pos
    if byte = 0uy then List.rev acc |> List.toArray
    else loop (byte :: acc) (pos + 1)
  if rva = 0 then ""
  else getRawOffset headers rva |> loop [] |> Text.Encoding.ASCII.GetString

let isNULLImportDir tbl =
  tbl.ImportLookupTableRVA = 0
  && tbl.ForwarderChain = 0
  && tbl.ImportDLLName = ""
  && tbl.ImportAddressTableRVA = 0

let readIDTEntry (binReader: BinReader) headers pos =
  { ImportLookupTableRVA = binReader.PeekInt32 pos
    ForwarderChain = binReader.PeekInt32 (pos + 8)
    ImportDLLName = binReader.PeekInt32 (pos + 12) |> readStr headers binReader
    ImportAddressTableRVA = binReader.PeekInt32 (pos + 16)
    DelayLoad = false }

let readDelayIDTEntry (binReader: BinReader) headers pos =
  { ImportLookupTableRVA = binReader.PeekInt32 (pos + 16)
    ForwarderChain = 0
    ImportDLLName = binReader.PeekInt32 (pos + 4) |> readStr headers binReader
    ImportAddressTableRVA = binReader.PeekInt32 (pos + 12)
    DelayLoad = true }

let parseImportDirectoryTableAux binReader headers readFn nextPos = function
  | 0 -> [||]
  | rva ->
    let rec loop acc pos =
      let tbl = readFn binReader headers pos
      if isNULLImportDir tbl then acc else loop (tbl :: acc) (nextPos pos)
    getRawOffset headers rva |> loop [] |> List.rev |> List.toArray

let parseImportDirectoryTable binReader (headers: PEHeaders) =
  let nextPos pos = pos + 20
  headers.PEHeader.ImportTableDirectory.RelativeVirtualAddress
  |> parseImportDirectoryTableAux binReader headers readIDTEntry nextPos

let parseDelayImportDirectoryTable binReader (headers: PEHeaders) =
  let nextPos pos = pos + 32
  headers.PEHeader.DelayImportTableDirectory.RelativeVirtualAddress
  |> parseImportDirectoryTableAux binReader headers readDelayIDTEntry nextPos

let parseILTEntry (binReader: BinReader) headers idt mask rva =
  let dllname = idt.ImportDLLName
  if rva &&& mask <> 0UL then
    ImportByOrdinal (uint16 rva |> int16, dllname)
  else
    let rva = 0x7fffffffUL &&& rva |> int
    let hint = getRawOffset headers rva |> binReader.PeekInt16
    let funname = readStr headers binReader (rva + 2)
    ImportByName (hint, funname, dllname)

let computeRVAMaskForILT wordSize =
  if wordSize = WordSize.Bit32 then 0x80000000UL
  else 0x8000000000000000UL

let parseILT binReader headers wordSize map idt =
  let skip = if wordSize = WordSize.Bit32 then 4 else 8
  let mask = computeRVAMaskForILT wordSize
  let rec loop map rvaOffset pos =
    let rva = FileHelper.peekUIntOfType binReader wordSize pos
    if rva = 0UL then map
    else
      let entry = parseILTEntry binReader headers idt mask rva
      let map = Map.add (idt.ImportAddressTableRVA + rvaOffset) entry map
      loop map (rvaOffset + skip) (pos + skip)
  if idt.ImportLookupTableRVA <> 0 then idt.ImportLookupTableRVA
  else idt.ImportAddressTableRVA
  |> getRawOffset headers
  |> loop map 0

let parseImports (binReader: BinReader) (headers: PEHeaders) wordSize =
  let mainImportTable = parseImportDirectoryTable binReader headers
  let delayImportTable = parseDelayImportDirectoryTable binReader headers
  Array.append mainImportTable delayImportTable
  |> Array.toList
  |> List.fold (parseILT binReader headers wordSize) Map.empty

let readExportDirectoryTableEntry (binReader: BinReader) headers pos =
  { ExportDLLName = binReader.PeekInt32 (pos + 12) |> readStr headers binReader
    OrdinalBase = binReader.PeekInt32 (pos + 16)
    AddressTableEntries = binReader.PeekInt32 (pos + 20)
    NumNamePointers = binReader.PeekInt32 (pos + 24)
    ExportAddressTableRVA = binReader.PeekInt32 (pos + 28)
    NamePointerRVA = binReader.PeekInt32 (pos + 32)
    OrdinalTableRVA = binReader.PeekInt32 (pos + 36) }

let parseEAT (binReader: BinReader) headers (sec: SectionHeader) edt =
  let lowerbound = sec.VirtualAddress
  let upperbound = sec.VirtualAddress + sec.VirtualSize
  let getEntry rva =
    if rva < lowerbound || rva > upperbound then ExportRVA rva
    else ForwarderRVA rva
  let rec loop acc cnt pos =
    if cnt = 0 then List.rev acc |> List.toArray
    else let rva = binReader.PeekInt32 (pos)
         loop (getEntry rva :: acc) (cnt - 1) (pos + 4)
  match edt.ExportAddressTableRVA with
  | 0 -> [||]
  | rva -> getRawOffset headers rva |> loop [] edt.AddressTableEntries

/// Parse Export Name Pointer Table (ENPT).
let parseENPT (binReader: BinReader) headers edt =
  let rec loop acc cnt pos1 pos2 =
    if cnt = 0 then acc
    else let str = binReader.PeekInt32 (pos1) |> readStr headers binReader
         let ord = binReader.PeekInt16 (pos2)
         loop ((str, ord) :: acc) (cnt - 1) (pos1 + 4) (pos2 + 2)
  if edt.NamePointerRVA = 0 then []
  else
    let offset1 = edt.NamePointerRVA |> getRawOffset headers
    let offset2 = edt.OrdinalTableRVA |> getRawOffset headers
    loop [] edt.NumNamePointers offset1 offset2

let buildExportTable binReader headers sec edt =
  let addrtbl = parseEAT binReader headers sec edt
  let folder map (name, ord) =
    match addrtbl.[int ord] with
    | ExportRVA rva ->
      let addr = addrFromRVA headers.PEHeader.ImageBase rva
      Map.add addr name map
    | _ -> map
  parseENPT binReader headers edt
  |> List.fold folder Map.empty

let parseExports binReader (headers: PEHeaders) =
  match headers.PEHeader.ExportTableDirectory.RelativeVirtualAddress with
  | 0 -> Map.empty
  | rva ->
    let idx = findSectionIndex headers rva
    let sec = headers.SectionHeaders.[idx]
    getRawOffset headers rva
    |> readExportDirectoryTableEntry binReader headers
    |> buildExportTable binReader headers sec

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

let parseRelocation (binReader: BinReader) (hdrs: PEHeaders) =
  match hdrs.PEHeader.BaseRelocationTableDirectory.RelativeVirtualAddress with
  | 0 -> List.empty
  | rva ->
    let hdrOffset = getRawOffset hdrs rva
    let upperBound = hdrOffset + hdrs.PEHeader.BaseRelocationTableDirectory.Size
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
  | None ->
    let pdbPath = IO.Path.ChangeExtension (execpath, "pdb")
    if IO.File.Exists pdbPath then IO.File.ReadAllBytes pdbPath |> parsePDB
    else []
  | Some rawpdb -> parsePDB rawpdb

let updatePDBInfo baseAddr sechdrs mAddr mName lst (sym: PESymbol) =
  let secNum = int sym.Segment - 1
  match Array.tryItem secNum (sechdrs: SectionHeader []) with
  | Some sec ->
    let addr = baseAddr + uint64 sec.VirtualAddress + uint64 sym.Address
    let sym = { sym with Address = addr }
    struct (Map.add addr sym mAddr, Map.add sym.Name sym mName, sym :: lst)
  | None -> struct (mAddr, mName, lst)

let buildPDBInfo baseAddr sechdrs symbs =
  let rec folder mAddr mName lst = function
    | sym :: rest ->
      let struct (mAddr, mName, lst) =
        updatePDBInfo baseAddr sechdrs mAddr mName lst sym
      folder mAddr mName lst rest
    | [] ->
      { SymbolByAddr = mAddr
        SymbolByName = mName
        SymbolArray = List.rev lst |> List.toArray }
  symbs
  |> folder Map.empty Map.empty []

let invRanges wordSize baseAddr sechdrs getNextStartAddr =
  sechdrs
  |> Array.sortBy (fun (s: SectionHeader) -> s.VirtualAddress)
  |> Array.fold (fun (set, saddr) s ->
    let myaddr = uint64 s.VirtualAddress + baseAddr
    let n = getNextStartAddr myaddr s
    FileHelper.addInvRange set saddr myaddr, n) (IntervalSet.empty, 0UL)
  |> FileHelper.addLastInvRange wordSize

let computeInvalidAddrRanges wordSize baseAddr sechdrs =
  invRanges wordSize baseAddr sechdrs (fun a s -> a + uint64 s.VirtualSize)

let computeNotInFileRanges wordSize baseAddr sechdrs =
  invRanges wordSize baseAddr sechdrs (fun a s -> a + uint64 s.SizeOfRawData)

let parseImage execpath rawpdb binReader (hdrs: PEHeaders) =
  let wordSize = magicToWordSize hdrs.PEHeader.Magic
  let baseAddr = hdrs.PEHeader.ImageBase
  let sechdrs = hdrs.SectionHeaders |> Seq.toArray
  { PEHeaders = hdrs
    BaseAddr = baseAddr
    SectionHeaders = sechdrs
    ImportMap= parseImports binReader hdrs wordSize
    ExportMap = parseExports binReader hdrs
    RelocBlocks = parseRelocation binReader hdrs
    WordSize = wordSize
    PDB = getPDBSymbols execpath rawpdb |> buildPDBInfo baseAddr sechdrs
    InvalidAddrRanges = computeInvalidAddrRanges wordSize baseAddr sechdrs
    NotInFileRanges = computeNotInFileRanges wordSize baseAddr sechdrs
    BinReader = binReader }

let getCoffWordSize = function
  | Machine.Alpha64
  | Machine.Arm64
  | Machine.Amd64 -> WordSize.Bit64
  | _ -> WordSize.Bit32

let parseCoff binReader (hdrs: PEHeaders) =
  let coff = hdrs.CoffHeader
  let wordSize = getCoffWordSize coff.Machine
  let sechdrs = hdrs.SectionHeaders |> Seq.toArray
  let emptyPDB =
    { SymbolByAddr = Map.empty; SymbolByName = Map.empty; SymbolArray = [||] }
  { PEHeaders = hdrs
    BaseAddr = 0UL
    SectionHeaders = sechdrs
    ImportMap= Map.empty
    ExportMap = Map.empty
    RelocBlocks = []
    WordSize = wordSize
    PDB = emptyPDB
    InvalidAddrRanges = IntervalSet.empty
    NotInFileRanges = IntervalSet.empty
    BinReader = binReader }

let parsePE execpath rawpdb binReader (peReader: PEReader) =
  let hdrs = peReader.PEHeaders
  if hdrs.IsCoffOnly then parseCoff binReader hdrs
  else parseImage execpath rawpdb binReader hdrs

let parse bytes execpath rawpdb =
  let binReader = BinReader.Init (bytes)
  use stream = new IO.MemoryStream (bytes)
  use peReader = new PEReader (stream, PEStreamOptions.Default)
  parsePE execpath rawpdb binReader peReader

