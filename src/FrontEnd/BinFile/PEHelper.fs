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

module internal B2R2.FrontEnd.BinFile.PE.Helper

open System
open B2R2
open B2R2.Monads
open B2R2.FrontEnd.BinFile
open System.Reflection.PortableExecutable

let [<Literal>] secText = ".text"

let machineToArch = function
  | Machine.I386 -> Arch.IntelX86
  | Machine.Amd64 | Machine.IA64 -> Arch.IntelX64
  | Machine.Arm -> Arch.ARMv7
  | Machine.Arm64 -> Arch.AARCH64
  | _ -> raise InvalidISAException

let getISA pe =
  let arch = machineToArch pe.PEHeaders.CoffHeader.Machine
  ISA.Init arch Endian.Little

let getFileType pe =
  let c = pe.PEHeaders.CoffHeader.Characteristics
  if c.HasFlag Characteristics.Dll then FileType.LibFile
  elif c.HasFlag Characteristics.ExecutableImage then FileType.ExecutableFile
  else FileType.ObjFile

let getWordSize pe =
  match pe.PEHeaders.PEHeader.Magic with
  | PEMagic.PE32 -> WordSize.Bit32
  | PEMagic.PE32Plus -> WordSize.Bit64
  | _ -> raise InvalidWordSizeException

let isNXEnabled pe =
  let hdrs = pe.PEHeaders
  if hdrs.IsCoffOnly then false
  else hdrs.PEHeader.DllCharacteristics.HasFlag DllCharacteristics.NxCompatible

let isRelocatable pe =
  let hdrs = pe.PEHeaders
  if hdrs.IsCoffOnly then true
  else hdrs.PEHeader.DllCharacteristics.HasFlag DllCharacteristics.DynamicBase

let getEntryPoint pe =
  if pe.PEHeaders.IsCoffOnly then None
  else
    let entry = pe.PEHeaders.PEHeader.AddressOfEntryPoint
    if entry = 0 then None
    else uint64 entry + pe.BaseAddr |> Some

let inline addrFromRVA baseAddr rva =
  uint64 rva + baseAddr

let secFlagToSectionKind (flags: SectionCharacteristics) =
  if flags.HasFlag SectionCharacteristics.MemExecute then
    SectionKind.ExecutableSection
  elif flags.HasFlag SectionCharacteristics.MemWrite then
    SectionKind.WritableSection
  else
    SectionKind.ExtraSection

let forwardInfoToStr = function
  | ForwardByName (name, dll) -> dll + "!" + name
  | ForwardByOrdinal (ord, dll) -> dll + "!#" + string ord

/// Some PE files have a section header indicating that the corresponding
/// section's size is zero even if it contains actual data, i.e.,
/// sHdr.VirtualSize = 0, but sHdr.SizeOfRawData <> 0. Thus, we should use this
/// function to get the size of sections (segments).
let getVirtualSectionSize (sec: SectionHeader) =
  let virtualSize = sec.VirtualSize
  if virtualSize = 0 then sec.SizeOfRawData else virtualSize

let secHdrToSection pe (sec: SectionHeader) =
  { Address = addrFromRVA pe.BaseAddr sec.VirtualAddress
    Kind = secFlagToSectionKind sec.SectionCharacteristics
    Size = getVirtualSectionSize sec |> uint64
    Name = sec.Name }

let getSectionsByName pe name =
  match pe.SectionHeaders |> Seq.tryFind (fun sec -> sec.Name = name) with
  | None -> Seq.empty
  | Some sec -> secHdrToSection pe sec |> Seq.singleton

let getTextStartAddr pe =
  match getSectionsByName pe secText |> Seq.tryHead with
  | None -> 0UL
  | Some sec -> sec.Address

let inline translateAddr pe addr =
  let rva = int (addr - pe.BaseAddr)
  match pe.FindSectionIdxFromRVA rva with
  | -1 -> raise InvalidAddrReadException
  | idx ->
    let sHdr = pe.SectionHeaders.[idx]
    rva + sHdr.PointerToRawData - sHdr.VirtualAddress

let pdbTypeToSymbKind = function
  | SymFlags.Function -> SymbolKind.FunctionType
  | _ -> SymbolKind.NoType

let pdbSymbolToSymbol (sym: PESymbol) =
  { Address = sym.Address
    Name = sym.Name
    Kind = pdbTypeToSymbKind sym.Flags
    Target = TargetKind.StaticSymbol
    LibraryName = "" }

let inline getStaticSymbols pe =
  pe.SymbolInfo.SymbolArray
  |> Array.map pdbSymbolToSymbol
  |> Array.toSeq

let getSymbolKindBySectionIndex pe idx =
  let ch = pe.SectionHeaders.[idx].SectionCharacteristics
  if ch.HasFlag SectionCharacteristics.MemExecute then SymbolKind.FunctionType
  else SymbolKind.ObjectType

let getImportSymbols pe =
  let conv acc rva imp =
    match imp with
    | ImportByOrdinal (_, dllname) ->
      { Address = addrFromRVA pe.BaseAddr rva
        Name = ""
        Kind = SymbolKind.ExternFunctionType
        Target = TargetKind.DynamicSymbol
        LibraryName = dllname } :: acc
    | ImportByName (_, funname, dllname) ->
      { Address = addrFromRVA pe.BaseAddr rva
        Name = funname
        Kind = SymbolKind.ExternFunctionType
        Target = TargetKind.DynamicSymbol
        LibraryName = dllname } :: acc
  pe.ImportMap
  |> Map.fold conv []
  |> List.rev

let getExportSymbols pe =
  let localExportFolder acc addr exp =
    let rva = int (addr - pe.BaseAddr)
    match pe.FindSectionIdxFromRVA rva with
    | -1 -> acc
    | idx ->
      { Address = addr
        Name = exp
        Kind = getSymbolKindBySectionIndex pe idx
        Target = TargetKind.DynamicSymbol
        LibraryName = "" } :: acc
  let forwardedExportFolder acc name forwardInfo =
    { Address = 0UL
      Name = name
      Kind = SymbolKind.FunctionType
      Target = TargetKind.DynamicSymbol
      LibraryName = forwardInfoToStr forwardInfo } :: acc
  let temp = Map.fold localExportFolder [] pe.ExportMap
  Map.fold forwardedExportFolder temp pe.ForwardMap

let getAllDynamicSymbols pe =
  let isym = getImportSymbols pe
  let esym = getExportSymbols pe
  List.append isym esym

let getDynamicSymbols pe excludeImported =
  let excludeImported = defaultArg excludeImported false
  if excludeImported then getExportSymbols pe else getAllDynamicSymbols pe
  |> List.toSeq

let getSymbols pe =
  let s = getStaticSymbols pe
  let d = getAllDynamicSymbols pe
  Seq.append s d

let getRelocationSymbols pe =
  pe.RelocBlocks
  |> Seq.collect (fun block ->
    block.Entries |> Seq.map(fun entry -> (block, entry)))
  |> Seq.map (fun (block, entry) -> {
    Address = uint64 (block.PageRVA + uint32 entry.Offset)
    Name = String.Empty
    Kind = SymbolKind.NoType
    Target = TargetKind.DynamicSymbol
    LibraryName = String.Empty
  })

let getSections pe =
  pe.SectionHeaders
  |> Array.map (secHdrToSection pe)
  |> Array.toSeq

let getSectionsByAddr pe addr =
  let rva = int (addr - pe.BaseAddr)
  match pe.FindSectionIdxFromRVA rva with
  | -1 -> Seq.empty
  | idx ->
    pe.SectionHeaders.[idx] |> secHdrToSection pe |> Seq.singleton

let getTextSections pe =
  getSectionsByName pe secText

let getImportTable pe =
  pe.ImportMap
  |> Map.fold (fun acc addr info ->
       match info with
       | ImportByOrdinal (_, dllname) ->
         { FuncName = ""
           LibraryName = dllname
           TrampolineAddress = 0UL
           TableAddress = addrFromRVA pe.BaseAddr addr } :: acc
       | ImportByName (_, fname, dllname) ->
         { FuncName = fname
           LibraryName = dllname
           TrampolineAddress = 0UL
           TableAddress = addrFromRVA pe.BaseAddr addr } :: acc) []
  |> List.sortBy (fun entry -> entry.TableAddress)
  |> List.toSeq

let isImportTable pe addr =
  let rva = int (addr - pe.BaseAddr)
  Map.containsKey rva pe.ImportMap

let getSecPermission (chr: SectionCharacteristics) =
  let x = if chr.HasFlag SectionCharacteristics.MemExecute then 1 else 0
  let w = if chr.HasFlag SectionCharacteristics.MemWrite then 2 else 0
  let r = if chr.HasFlag SectionCharacteristics.MemRead then 4 else 0
  r + w + x |> LanguagePrimitives.EnumOfValue

let getSegments pe =
  let secToSegment (sec: SectionHeader) =
    { Address = uint64 sec.VirtualAddress + pe.BaseAddr
      Size = getVirtualSectionSize sec |> uint64
      Permission = getSecPermission sec.SectionCharacteristics }
  pe.SectionHeaders
  |> Seq.map secToSegment

let private findSymFromIAT addr pe =
  let rva = int (addr - pe.BaseAddr)
  match Map.tryFind rva pe.ImportMap with
  | Some (ImportByName (_, n, _)) -> Some n
  | _ -> None

let private findSymFromEAT addr pe () =
  match Map.tryFind addr pe.ExportMap with
  | Some n -> Some n
  | _ -> None

let tryFindSymbolFromBinary pe addr =
  match findSymFromIAT addr pe |> OrElse.bind (findSymFromEAT addr pe) with
  | None -> Error ErrorCase.SymbolNotFound
  | Some s -> Ok s

let tryFindSymbolFromPDB pe addr =
  match Map.tryFind addr pe.SymbolInfo.SymbolByAddr with
  | None -> Error ErrorCase.SymbolNotFound
  | Some s -> Ok s.Name

let tryFindFuncSymb pe addr =
  if pe.SymbolInfo.SymbolArray.Length = 0 then tryFindSymbolFromBinary pe addr
  else tryFindSymbolFromPDB pe addr

let inline isValidAddr pe addr =
  IntervalSet.containsAddr addr pe.InvalidAddrRanges |> not

let inline isValidRange pe range =
  IntervalSet.findAll range pe.InvalidAddrRanges |> List.isEmpty

let inline isInFileAddr pe addr =
  IntervalSet.containsAddr addr pe.NotInFileRanges |> not

let inline isInFileRange pe range =
  IntervalSet.findAll range pe.NotInFileRanges |> List.isEmpty

let inline isExecutableAddr pe addr =
  IntervalSet.containsAddr addr pe.ExecutableRanges

let inline getNotInFileIntervals pe range =
  IntervalSet.findAll range pe.NotInFileRanges
  |> List.map (FileHelper.trimByRange range)
  |> List.toSeq

let isPE bytes offset =
  try
    let bs = Array.sub bytes offset (Array.length bytes - offset)
    use stream = new IO.MemoryStream (bs)
    use reader = new PEReader (stream, PEStreamOptions.Default)
    reader.PEHeaders.CoffHeader.Machine |> machineToArch |> ignore
    true
  with _ ->
    false

// vim: set tw=80 sts=2 sw=2:
