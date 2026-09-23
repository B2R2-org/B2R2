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

open B2R2
open B2R2.Collections
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.PE.PEUtils
open B2R2.FrontEnd.BinLifter

/// Main PE format representation.
type internal PE =
  { /// Every header of the file.
    Header: Header
    /// Image base address.
    BaseAddr: Addr
    /// Section headers.
    SectionHeaders: SectionHeader[]
    /// RVA to imported symbol, read when it is first asked for. A table is
    /// no part of what opening a file takes, and a file names four of them
    /// that reading the whole of costs more than everything else here put
    /// together, so each waits until something wants it.
    ImportedSymbols: Lazy<Map<int, ImportedSymbol>>
    /// Exported symbols, read when they are first asked for.
    ExportedSymbols: Lazy<ExportedSymbolStore>
    /// List of relocation blocks, read when they are first asked for.
    RelocBlocks: Lazy<BaseRelocationBlock list>
    /// Word size for the binary.
    WordSize: WordSize
    /// Symbol information, read when it is first asked for. For an image
    /// that is a PDB beside it, which is a file of its own to go and read.
    Symbols: Lazy<SymbolStore>
    /// Invalid address ranges.
    InvalidAddrRanges: IntervalSet
    /// Not-in-file address ranges.
    NotInFileRanges: IntervalSet
    /// Executable address ranges.
    ExecutableRanges: IntervalSet
    /// A function for finding section index for a given rva (int).
    FindSectionIdxFromRVA: int -> int
    /// BinReader
    BinReader: IBinReader }

let [<Literal>] SecText = Section.Text

/// Returns what the image says about the PDB it was built with, or none for
/// an image that says nothing. An object file has no optional header for a
/// debug directory to be named in.
let tryGetCodeViewInfo bytes pe =
  match pe.Header.OptionalHeader with
  | None -> None
  | Some hdr -> CodeViewInfo.tryFind bytes pe.BinReader pe.SectionHeaders hdr

/// Returns the build ID of the binary, which is the GUID that the CodeView
/// entry of its debug directory carries. It names the PDB built beside the
/// binary, and a build made without one carries no such entry.
let getBuildId bytes pe =
  match tryGetCodeViewInfo bytes pe with
  | Some cv -> cv.Guid
  | None -> [||]

let isNXEnabled pe =
  match pe.Header.OptionalHeader with
  | None -> false
  | Some hdr -> hdr.DllCharacteristics.HasFlag DllCharacteristics.NxCompatible

let isPIE pe =
  match pe.Header.OptionalHeader with
  | None ->
    false
  | Some hdr ->
    not (pe.Header.CoffHeader.Characteristics.HasFlag Characteristics.Dll)
    && hdr.DllCharacteristics.HasFlag DllCharacteristics.DynamicBase

let isBaseRelative pe =
  match pe.Header.OptionalHeader with
  | None -> true
  | Some hdr -> hdr.DllCharacteristics.HasFlag DllCharacteristics.DynamicBase

let getEntryPoint pe =
  match pe.Header.OptionalHeader with
  | None ->
    None
  | Some hdr ->
    let entry = hdr.AddressOfEntryPoint
    if entry = 0 then None else uint64 entry + pe.BaseAddr |> Some

/// Returns where the image wants to be loaded, which is what every address
/// it names is relative to. An object file names no base of its own, every
/// address of one being relative to the section it sits in instead.
let getImageBase pe =
  match pe.Header.OptionalHeader with
  | None -> 0UL
  | Some hdr -> hdr.ImageBase

let inline isSectionExecutableByIndex pe idx =
  pe.SectionHeaders[idx].SectionCharacteristics.HasFlag
  <| SectionCharacteristics.MemExecute

let getImportTable pe =
  [| for KeyValue(addr, info) in pe.ImportedSymbols.Value do
       let name, dllname =
         match info with
         | ByOrdinal(ord, dll) -> $"[{ord.ToString()}]", dll
         | ByName(_, fname, dll) -> fname, dll
       { Name = name
         LibraryName = dllname
         TrampolineAddress = None
         TableAddress = addrFromRVA pe.BaseAddr addr } |]
  |> Array.sortBy (fun entry -> entry.TableAddress)

let isImportTable pe addr =
  let rva = int (addr - pe.BaseAddr)
  Map.containsKey rva pe.ImportedSymbols.Value

let getSecPermission (chr: SectionCharacteristics) =
  let x = if chr.HasFlag SectionCharacteristics.MemExecute then 1 else 0
  let w = if chr.HasFlag SectionCharacteristics.MemWrite then 2 else 0
  let r = if chr.HasFlag SectionCharacteristics.MemRead then 4 else 0
  r + w + x |> LanguagePrimitives.EnumOfValue

let private findSymFromIAT addr pe =
  let rva = int (addr - pe.BaseAddr)
  match Map.tryFind rva pe.ImportedSymbols.Value with
  | Some(ByName(_, n, _)) -> Some n
  | _ -> None

let private findSymFromEAT addr pe () =
  match pe.ExportedSymbols.Value.TryFind addr with
  | None -> None
  | Some [] -> None
  | Some(n :: _) -> Some n

let tryFindSymbolFromBinary pe addr =
  match findSymFromIAT addr pe
        |> Option.orElseWith (findSymFromEAT addr pe) with
  | None -> Error ErrorCase.SymbolNotFound
  | Some s -> Ok s

let tryFindSymbolFromPDB pe addr =
  match pe.Symbols.Value.SymbolByAddr.TryGetValue addr with
  | false, _ -> Error ErrorCase.SymbolNotFound
  | true, s -> Ok s.Name

let inline isValidAddr pe addr =
  IntervalSet.containsAddr addr pe.InvalidAddrRanges |> not

let inline isValidRange pe range =
  IntervalSet.overlapsRange range pe.InvalidAddrRanges |> not

let inline isAddrMappedToFile pe addr =
  IntervalSet.containsAddr addr pe.NotInFileRanges |> not

let inline isRangeMappedToFile pe range =
  IntervalSet.overlapsRange range pe.NotInFileRanges |> not

let inline isExecutableAddr pe addr =
  IntervalSet.containsAddr addr pe.ExecutableRanges

/// Checks whether a loader maps the given address into the given section,
/// whether or not the file keeps bytes for it.
let private sectionMaps (sec: SectionHeader) baseAddr addr =
  let vma = uint64 sec.VirtualAddress + baseAddr
  addr >= vma && addr < vma + uint64 (getVirtualSectionSize sec)

/// The section the last lookup settled on, which the next one tries before
/// scanning the table. It is a hint and never an answer: it is taken only
/// where it passes the very test a scan would apply, so a stale one costs a
/// bounds check and nothing else.
let mutable private lastSectionHit = 0

/// Returns the index of the section a loader maps the given address into, or
/// -1 where none of them does.
let private findSectionMapping (secs: SectionHeader[]) baseAddr addr =
  let hint = lastSectionHit
  if hint < secs.Length && sectionMaps secs[hint] baseAddr addr then
    hint
  else
    let mutable idx = 0
    let mutable found = -1
    while found < 0 && idx < secs.Length do
      if sectionMaps secs[idx] baseAddr addr then found <- idx
      else idx <- idx + 1
    if found >= 0 then lastSectionHit <- found else ()
    found

/// Returns a pointer to the given address, bounded by the section a loader
/// maps it into. An address such a section gives room to but the file keeps
/// no bytes for names no file offset and gives a virtual pointer; an address
/// no section maps at all gives a null one.
let boundedPointerOf pe addr =
  match findSectionMapping pe.SectionHeaders pe.BaseAddr addr with
  | -1 ->
    BinFilePointer.Null
  | idx ->
    let sec = pe.SectionHeaders[idx]
    let vma = uint64 sec.VirtualAddress + pe.BaseAddr
    if addr < vma + uint64 sec.SizeOfRawData then
      let offset = sec.PointerToRawData + int (addr - vma)
      let maxOffset = sec.PointerToRawData + sec.SizeOfRawData - 1
      let maxAddr = vma + uint64 sec.SizeOfRawData - 1UL
      BinFilePointer.CreateFileBacked(addr, maxAddr, offset, maxOffset)
    else
      let vmaSize = uint64 (getVirtualSectionSize sec)
      BinFilePointer.CreateVirtual(addr, vma + vmaSize - 1UL)

let peMachineToISA = function
  | Machine.I386 -> ISA(Architecture.Intel, WordSize.Bit32)
  | Machine.Amd64 | Machine.IA64 -> ISA(Architecture.Intel, WordSize.Bit64)
  | Machine.Arm -> ISA(Architecture.ARMv7, WordSize.Bit32)
  | Machine.Arm64 -> ISA(Architecture.ARMv8, WordSize.Bit64)
  | _ -> raise InvalidISAException

/// Returns the ISA a PE image's instructions are in. A managed image that is
/// pure IL is CIL and nothing else; one that is not holds native code and is
/// entered through it, so the ISA that describes it is that code's, and what
/// IL it also holds is a fact about the file rather than about its
/// instruction set. ILOnly is one flag among several a COR header carries, so
/// it has to be read as a flag.
let headerToISA (hdr: Header) =
  match hdr.CorHeader with
  | Some cor when cor.Flags.HasFlag CorFlags.ILOnly -> ISA Architecture.CIL
  | _ -> peMachineToISA hdr.CoffHeader.Machine

/// Return Architecture from the PE header. If the given binary is invalid,
/// return an Error.
let getISA (bytes: byte[]) =
  try
    Header.parse bytes (BinReader.Init Endian.Little) |> headerToISA |> Ok
  with _ ->
    Error ErrorCase.InvalidFormat
