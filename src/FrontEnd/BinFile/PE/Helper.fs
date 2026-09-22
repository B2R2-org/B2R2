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
    BinReader: IBinReader }

let [<Literal>] SecText = Section.Text

/// Represents the debug directory entry kind that names a PDB, which the
/// specification calls DEBUG_TYPE_CODEVIEW.
let private codeViewType = 2u

/// Represents the signature of the CodeView record form that carries a
/// GUID, which reads as "RSDS".
let private codeViewSignature = 0x53445352u

/// Returns where the debug directory sits in the file and how many entries it
/// holds, or none for a file that carries none. An object file has no
/// optional header for the directory to be named in.
let private tryFindDebugDirectory pe =
  match pe.Header.OptionalHeader with
  | None ->
    None
  | Some hdr ->
    let dir = hdr.Directory DirectoryKind.Debug
    match tryGetDirectoryOffset pe.SectionHeaders dir with
    | Some offset when dir.Size >= 28 -> Some(offset, dir.Size / 28)
    | _ -> None

/// Reads the GUID out of the CodeView record at the given file offset. Only
/// the RSDS form carries one, and it is what every toolchain since VC7
/// writes; the older NB10 form names its PDB by a timestamp instead.
let private readCodeViewGuid (bytes: byte[]) (reader: IBinReader) offset =
  if offset < 0 || offset + 20 > bytes.Length then
    [||]
  else
    let span = System.ReadOnlySpan(bytes, offset, 20)
    if reader.ReadUInt32(span, 0) = codeViewSignature then
      span.Slice(4, 16).ToArray()
    else
      [||]

/// Reads the GUID of one debug directory entry, which only a CodeView entry
/// carries. The entry names its record twice, by address and by file offset,
/// and the offset is what a reader of the file on disk can follow.
let private readEntryGuid bytes (reader: IBinReader) (span: ByteSpan) =
  if reader.ReadUInt32(span, 12) = codeViewType then
    readCodeViewGuid bytes reader (reader.ReadInt32(span, 24))
  else
    [||]

let rec private findCodeViewGuid (bytes: byte[]) reader offset count =
  if count = 0 || offset + 28 > bytes.Length then
    [||]
  else
    let span = System.ReadOnlySpan(bytes, offset, 28)
    let guid = readEntryGuid bytes reader span
    if Array.isEmpty guid then
      findCodeViewGuid bytes reader (offset + 28) (count - 1)
    else
      guid

/// Returns the build ID of the binary, which is the GUID that the CodeView
/// entry of its debug directory carries. It names the PDB built beside the
/// binary, and a build made without one carries no such entry.
let getBuildId bytes pe =
  match tryFindDebugDirectory pe with
  | Some(offset, count) -> findCodeViewGuid bytes pe.BinReader offset count
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
  [| for KeyValue(addr, info) in pe.ImportedSymbols do
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
  Map.containsKey rva pe.ImportedSymbols

let getSecPermission (chr: SectionCharacteristics) =
  let x = if chr.HasFlag SectionCharacteristics.MemExecute then 1 else 0
  let w = if chr.HasFlag SectionCharacteristics.MemWrite then 2 else 0
  let r = if chr.HasFlag SectionCharacteristics.MemRead then 4 else 0
  r + w + x |> LanguagePrimitives.EnumOfValue

let private findSymFromIAT addr pe =
  let rva = int (addr - pe.BaseAddr)
  match Map.tryFind rva pe.ImportedSymbols with
  | Some(ByName(_, n, _)) -> Some n
  | _ -> None

let private findSymFromEAT addr pe () =
  match pe.ExportedSymbols.TryFind addr with
  | None -> None
  | Some [] -> None
  | Some(n :: _) -> Some n

let tryFindSymbolFromBinary pe addr =
  match findSymFromIAT addr pe
        |> Option.orElseWith (findSymFromEAT addr pe) with
  | None -> Error ErrorCase.SymbolNotFound
  | Some s -> Ok s

let tryFindSymbolFromPDB pe addr =
  match pe.Symbols.SymbolByAddr.TryGetValue addr with
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
