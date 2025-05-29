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
open B2R2.Collections
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.FileHelper
open B2R2.FrontEnd.BinFile.PE.PEUtils
open B2R2.FrontEnd.BinFile.PE.Helper

let magicToWordSize = function
  | PEMagic.PE32 -> WordSize.Bit32
  | PEMagic.PE32Plus -> WordSize.Bit64
  | _ -> raise InvalidWordSizeException

let parsePDB reader (pdbBytes: byte[]) =
  let span = ReadOnlySpan pdbBytes
  if PDB.isValidHeader span reader then ()
  else raise InvalidFileFormatException
  PDB.parse span reader

let getPDBSymbols reader (execpath: string) = function
  | [||] ->
    let pdbPath = IO.Path.ChangeExtension (execpath, "pdb")
    if IO.File.Exists pdbPath then
      IO.File.ReadAllBytes pdbPath |> parsePDB reader
    else []
  | rawpdb -> parsePDB reader rawpdb

let updatePDBInfo baseAddr secs mAddr mName lst (sym: Symbol) =
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
    ImportedSymbols = Map.empty
    ExportedSymbols = ExportedSymbolStore ()
    RelocBlocks = []
    WordSize = wordSize
    Symbols = Coff.getSymbols bytes reader coff
    InvalidAddrRanges = IntervalSet.empty
    NotInFileRanges = IntervalSet.empty
    ExecutableRanges = execRanges baseAddr secs
    FindSectionIdxFromRVA = findSectionIdxFromRVA
    BinReader = reader }

let parseImage execpath rawpdb baseAddr bytes reader (hdrs: PEHeaders) =
  let wordSize = magicToWordSize hdrs.PEHeader.Magic
  let baseAddr = defaultArg baseAddr hdrs.PEHeader.ImageBase
  let secs = hdrs.SectionHeaders |> Seq.toArray
  { PEHeaders = hdrs
    BaseAddr = baseAddr
    SectionHeaders = secs
    ImportedSymbols = ImportedSymbolStore.parse bytes reader hdrs secs wordSize
    ExportedSymbols = ExportedSymbolStore (baseAddr, bytes, reader, hdrs, secs)
    RelocBlocks = BaseRelocationTable.parse bytes reader hdrs secs
    WordSize = wordSize
    Symbols = getPDBSymbols reader execpath rawpdb |> buildPDBInfo baseAddr secs
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
