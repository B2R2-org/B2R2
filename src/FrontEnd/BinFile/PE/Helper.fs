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

open System.IO
open System.Reflection.PortableExecutable
open B2R2
open B2R2.Collections
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.PE.PEUtils
open B2R2.FrontEnd.BinLifter

/// Main PE format representation.
type PE = {
  /// PE headers.
  PEHeaders: PEHeaders
  /// Image base address.
  BaseAddr: Addr
  /// Section headers.
  SectionHeaders: SectionHeader[]
  /// RVA to imported symbol.
  ImportedSymbols: Map<int, ImportedSymbol>
  /// Exported symbols.
  ExportedSymbols: ExportedSymbolStore
  /// List of relocation blocks
  RelocBlocks: BaseRelocationBlock list
  /// Word size for the binary.
  WordSize: WordSize
  /// Symbol information.
  Symbols: SymbolStore
  /// Invalid address ranges.
  InvalidAddrRanges: IntervalSet
  /// Not-in-file address ranges.
  NotInFileRanges: IntervalSet
  /// Executable address ranges.
  ExecutableRanges: IntervalSet
  /// A function for finding section index for a given rva (int).
  FindSectionIdxFromRVA: int -> int
  /// BinReader
  BinReader: IBinReader
}

let [<Literal>] SecText = ".text"

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

/// Some PE files have a section header indicating that the corresponding
/// section's size is zero even if it contains actual data, i.e.,
/// sHdr.VirtualSize = 0, but sHdr.SizeOfRawData <> 0. Thus, we should use this
/// function to get the size of sections.
let getVirtualSectionSize (sec: SectionHeader) =
  let virtualSize = sec.VirtualSize
  if virtualSize = 0 then sec.SizeOfRawData else virtualSize

let inline translateAddr pe addr =
  let rva = int (addr - pe.BaseAddr)
  match pe.FindSectionIdxFromRVA rva with
  | -1 -> raise InvalidAddrReadException
  | idx ->
    let sHdr = pe.SectionHeaders[idx]
    rva + sHdr.PointerToRawData - sHdr.VirtualAddress

let inline isSectionExecutableByIndex pe idx =
  pe.SectionHeaders[idx].SectionCharacteristics.HasFlag
  <| SectionCharacteristics.MemExecute

let hasRelocationSymbols pe addr = (* FIXME: linear lookup is bad *)
  pe.RelocBlocks
  |> List.exists (fun block ->
    block.Entries
    |> Array.exists (fun entry ->
      uint64 (block.PageRVA + uint32 entry.Offset) = addr)
  )

let getImportTable pe =
  pe.ImportedSymbols
  |> Map.fold (fun acc addr info ->
       match info with
       | ByOrdinal (ord, dllname) ->
         { FuncName = "#" + ord.ToString()
           LibraryName = dllname
           TrampolineAddress = 0UL
           TableAddress = addrFromRVA pe.BaseAddr addr } :: acc
       | ByName (_, fname, dllname) ->
         { FuncName = fname
           LibraryName = dllname
           TrampolineAddress = 0UL
           TableAddress = addrFromRVA pe.BaseAddr addr } :: acc) []
  |> List.sortBy (fun entry -> entry.TableAddress)
  |> List.toArray

let isImportTable pe addr =
  let rva = int (addr - pe.BaseAddr)
  Map.containsKey rva pe.ImportedSymbols

let getSecPermission (chr: SectionCharacteristics) =
  let x = if chr.HasFlag SectionCharacteristics.MemExecute then 1 else 0
  let w = if chr.HasFlag SectionCharacteristics.MemWrite then 2 else 0
  let r = if chr.HasFlag SectionCharacteristics.MemRead then 4 else 0
  r + w + x |> LanguagePrimitives.EnumOfValue

let private findSymFromIAT addr pe =
  let rva = int (addr - pe.BaseAddr)
  match Map.tryFind rva pe.ImportedSymbols with
  | Some (ByName (_, n, _)) -> Some n
  | _ -> None

let private findSymFromEAT addr pe () =
  match pe.ExportedSymbols.TryFind addr with
  | None -> None
  | Some [] -> None
  | Some (n :: _) -> Some n

let tryFindSymbolFromBinary pe addr =
  match findSymFromIAT addr pe
        |> Option.orElseWith (findSymFromEAT addr pe) with
  | None -> Error ErrorCase.SymbolNotFound
  | Some s -> Ok s

let tryFindSymbolFromPDB pe addr =
  match Map.tryFind addr pe.Symbols.SymbolByAddr with
  | None -> Error ErrorCase.SymbolNotFound
  | Some s -> Ok s.Name

let inline isValidAddr pe addr =
  IntervalSet.containsAddr addr pe.InvalidAddrRanges |> not

let inline isValidRange pe range =
  IntervalSet.findAll range pe.InvalidAddrRanges |> List.isEmpty

let inline isAddrMappedToFile pe addr =
  IntervalSet.containsAddr addr pe.NotInFileRanges |> not

let inline isRangeMappedToFile pe range =
  IntervalSet.findAll range pe.NotInFileRanges |> List.isEmpty

let inline isExecutableAddr pe addr =
  IntervalSet.containsAddr addr pe.ExecutableRanges

let peMachineToISA = function
  | Machine.I386 -> ISA (Architecture.Intel, WordSize.Bit32)
  | Machine.Amd64 | Machine.IA64 -> ISA (Architecture.Intel, WordSize.Bit64)
  | Machine.Arm -> ISA (Architecture.ARMv7, WordSize.Bit32)
  | Machine.Arm64 -> ISA (Architecture.ARMv8, WordSize.Bit64)
  | _ -> raise InvalidISAException

let peHeadersToISA (peHeaders: PEHeaders) =
  let corHeader = peHeaders.CorHeader
  if isNull corHeader then
    peHeaders.CoffHeader.Machine |> peMachineToISA
  else
    if corHeader.Flags = CorFlags.ILOnly then ISA CILKind.CILOnly
    else
      match peHeaders.CoffHeader.Machine with
      | Machine.I386 -> ISA CILKind.CILx86
      | Machine.Amd64 | Machine.IA64 -> ISA CILKind.CILx64
      | _ -> raise InvalidISAException

/// Return Architecture from the PE header. If the given binary is invalid,
/// return an Error.
let getISA (bytes: byte[]) =
  try
    use stream = new MemoryStream (bytes)
    use reader = new PEReader (stream, PEStreamOptions.Default)
    peHeadersToISA reader.PEHeaders |> Ok
  with _ ->
    Error ErrorCase.InvalidFormat

// vim: set tw=80 sts=2 sw=2:
