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
open System.Collections.Generic
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

let readPDB reader expected pdbBytes =
  if PDB.isValidHeader pdbBytes reader then ()
  else raise InvalidFileFormatException
  PDB.parse pdbBytes reader expected

/// Returns the symbols the given PDB holds. Whatever stops the read -- the
/// magic it leads with, the shape of the file system inside it, a stream
/// reaching past its end -- says the one thing a caller can act on: this is
/// not a PDB to read symbols out of. So every one of them reaches the caller
/// the same way, rather than as whichever read happened to find it first.
let parsePDB reader expected pdbBytes =
  try readPDB reader expected pdbBytes
  with e when not (Terminator.isCritical e) -> raise InvalidFileFormatException

/// Returns the symbols a PDB found beside the image holds, or none when there
/// is no reading it. Such a PDB is not one a caller asked for, so nothing
/// about it is a reason to fail to load the image it sits next to: not that it
/// is a portable PDB, which is what every .NET assembly built today ships and
/// is not the format read here, nor that it cannot be read at all.
let tryParsePDB reader expected pdbPath =
  try IO.File.ReadAllBytes pdbPath |> parsePDB reader expected
  with e when not (Terminator.isCritical e) -> []

/// Returns the paths to look for an image's PDB at, nearest first: the name
/// the image records, taken beside the image, and then the image's own name
/// under a .pdb extension. Only the name at the end of the recorded path
/// carries over, because the path itself is the one on the machine that built
/// the image: following it whole would have this reader open whatever file an
/// image names, anywhere it names one, including across a network.
let getPDBSearchPaths (execpath: string) (cv: CodeViewInfo) =
  let fallback = IO.Path.ChangeExtension(execpath, "pdb")
  let dir = IO.Path.GetDirectoryName fallback
  let name = cv.PDBPath.Substring(cv.PDBPath.LastIndexOfAny [| '\\'; '/' |] + 1)
  if name = "" || isNull dir then [ fallback ]
  else [ IO.Path.Combine(dir, name); fallback ]

/// Returns the symbols the PDB of the given image holds, where one is found
/// beside it. An image that names no PDB is not one to go looking for a file
/// next to, since nothing would say whether what turned up belonged to it.
let getPDBBesideImage reader execpath cv =
  match cv with
  | None ->
    []
  | Some info ->
    match List.tryFind IO.File.Exists (getPDBSearchPaths execpath info) with
    | Some path -> tryParsePDB reader cv path
    | None -> []

let getPDBSymbols reader execpath cv = function
  | [||] -> getPDBBesideImage reader execpath cv
  | rawpdb -> parsePDB reader cv rawpdb

let updatePDBInfo baseAddr secs lst (sym: Symbol) =
  let secNum = int sym.Segment - 1
  match Array.tryItem secNum (secs: SectionHeader []) with
  | Some sec ->
    let addr = baseAddr + uint64 sec.VirtualAddress + uint64 sym.Address
    { sym with Address = addr } :: lst
  | None ->
    lst

let buildPDBInfo baseAddr secs symbs =
  let rec folder lst = function
    | sym :: rest -> folder (updatePDBInfo baseAddr secs lst sym) rest
    | [] -> List.rev lst |> List.toArray
  let arr = folder [] symbs
  let byAddr = Dictionary<Addr, Symbol>()
  for sym in arr do byAddr[sym.Address] <- sym
  { SymbolByAddr = byAddr
    SymbolArray = arr }

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
    IntervalSet.add (AddrRange.create saddr (eaddr - 1UL)) set
    ) IntervalSet.empty

let parseCoff baseAddrOpt bytes reader (hdrs: Header) =
  let coff = hdrs.CoffHeader
  let baseAddr = defaultArg baseAddrOpt 0UL
  let wordSize = Coff.getWordSize coff.Machine
  let secs = hdrs.SectionHeaders
  (* An object naming no code section, as a data-only one and one built with
     LTCG do, has no index to hand back, and -1 is what every caller already
     reads as no section. *)
  let idx =
    secs
    |> Array.tryFindIndex (fun s -> s.Name.StartsWith SecText)
    |> Option.defaultValue -1
  let findSectionIdxFromRVA = fun _ -> idx
  { Header = hdrs
    BaseAddr = baseAddr
    SectionHeaders = secs
    ImportedSymbols = lazy Map.empty
    ExportedSymbols = lazy (ExportedSymbolStore())
    RelocBlocks = lazy []
    WordSize = wordSize
    Symbols = lazy (Coff.getSymbols bytes reader coff)
    InvalidAddrRanges = IntervalSet.empty
    NotInFileRanges = IntervalSet.empty
    ExecutableRanges = execRanges baseAddr secs
    FindSectionIdxFromRVA = findSectionIdxFromRVA
    BinReader = reader }

let parseImage execpath rawpdb baseAddr bytes reader (hdrs: Header) opt =
  let wordSize = magicToWordSize opt.Magic
  let baseAddr = defaultArg baseAddr opt.ImageBase
  let secs = hdrs.SectionHeaders
  let symbols =
    lazy
      let cv = CodeViewInfo.tryFind bytes reader secs opt
      getPDBSymbols reader execpath cv rawpdb |> buildPDBInfo baseAddr secs
  { Header = hdrs
    BaseAddr = baseAddr
    SectionHeaders = secs
    ImportedSymbols =
      lazy (ImportedSymbolStore.parse bytes reader opt secs wordSize)
    ExportedSymbols =
      lazy (ExportedSymbolStore(baseAddr, bytes, reader, opt, secs))
    RelocBlocks = lazy (BaseRelocationTable.parse bytes reader opt secs)
    WordSize = wordSize
    Symbols = symbols
    InvalidAddrRanges = computeInvalidAddrRanges wordSize baseAddr secs
    NotInFileRanges = computeNotInFileRanges wordSize baseAddr secs
    ExecutableRanges = execRanges baseAddr secs
    FindSectionIdxFromRVA = findSectionIndex secs
    BinReader = reader }

let parsePE execpath baseAddrOpt rawpdb bytes reader (hdrs: Header) =
  match hdrs.OptionalHeader with
  | None -> parseCoff baseAddrOpt bytes reader hdrs
  | Some opt -> parseImage execpath rawpdb baseAddrOpt bytes reader hdrs opt

let parse execpath (bytes: byte[]) baseAddrOpt rawpdb =
  let reader = BinReader.Init Endian.Little
  Header.parse bytes reader
  |> parsePE execpath baseAddrOpt rawpdb bytes reader
