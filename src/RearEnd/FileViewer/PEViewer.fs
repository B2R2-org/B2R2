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

module B2R2.RearEnd.FileViewer.PEViewer

open System.Reflection.PortableExecutable
open B2R2
open B2R2.FrontEnd.BinFile
open B2R2.RearEnd.FileViewer.Helper
open B2R2.RearEnd.Utils

let badAccess _ _ =
  raise InvalidFileFormatException

let translateChracteristics chars =
  let enumChars =
    System.Enum.GetValues (typeof<Characteristics>)
    :?> Characteristics []
    |> Array.toList
  let rec loop acc chars = function
    | [] -> List.rev acc
    | enumChar :: tail ->
      if uint64 enumChar &&& chars = uint64 enumChar then
        loop ((" - " + enumChar.ToString ()) :: acc) chars tail
      else
        loop acc chars tail
  loop [] chars enumChars

let dumpFileHeader _ (file: PEBinFile) =
  let hdr = file.PE.PEHeaders.CoffHeader
  out.PrintTwoCols
    "Machine:"
    (HexString.ofUInt64 (uint64 hdr.Machine)
    + String.wrapParen (hdr.Machine.ToString ()))
  out.PrintTwoCols
    "Number of sections:"
    (hdr.NumberOfSections.ToString ())
  out.PrintTwoCols
    "Time date stamp:"
    (hdr.TimeDateStamp.ToString ())
  out.PrintTwoCols
    "Pointer to symbol table:"
    (HexString.ofUInt64 (uint64 hdr.PointerToSymbolTable))
  out.PrintTwoCols
    "Size of optional header:"
    (HexString.ofUInt64 (uint64 hdr.SizeOfOptionalHeader))
  out.PrintTwoCols
    "Characteristics:"
    (HexString.ofUInt64 (uint64 hdr.Characteristics))
  translateChracteristics (uint64 hdr.Characteristics)
  |> List.iter (fun str -> out.PrintTwoCols "" str)

let translateSectionChracteristics chars =
  let enumChars =
    System.Enum.GetValues (typeof<SectionCharacteristics>)
    :?> SectionCharacteristics []
    |> Array.toList
  if chars = uint64 0 then
    [ " - TypeReg" ]
  else
    let rec loop acc chars = function
      | [] -> List.rev acc
      | enumChar :: t ->
        if uint64 enumChar &&& chars = uint64 enumChar
          && (uint64 enumChar <> 0UL) then
          loop ((" - " + enumChar.ToString ()) :: acc) chars t
        else
          loop acc chars t
    loop [] chars enumChars

let dumpSectionHeaders (opts: FileViewerOpts) (pe: PEBinFile) =
  let addrColumn = columnWidthOfAddr pe |> LeftAligned
  let file = pe :> IBinFile
  if opts.Verbose then
    let cfg = [ LeftAligned 4; addrColumn; addrColumn; LeftAligned 24
                LeftAligned 8; LeftAligned 8; LeftAligned 8; LeftAligned 8
                LeftAligned 8; LeftAligned 8; LeftAligned 8; LeftAligned 8
                LeftAligned 8 ]
    out.PrintRow (true, cfg,
      [ "Num"; "Start"; "End"; "Name"
        "VirtSize"; "VirtAddr"; "RawSize"; "RawPtr"
        "RelocPtr"; "LineNPtr"; "RelocNum"; "LineNNum"
        "Characteristics" ])
    out.PrintLine "  ---"
    pe.PE.SectionHeaders
    |> Array.iteri (fun idx s ->
      let startAddr = pe.PE.BaseAddr + uint64 s.VirtualAddress
      let size =
        uint64 (if s.VirtualSize = 0 then s.SizeOfRawData else s.VirtualSize)
      let characteristics = uint64 s.SectionCharacteristics
      out.PrintRow (true, cfg,
        [ String.wrapSqrdBracket (idx.ToString ())
          (Addr.toString file.ISA.WordSize startAddr)
          (Addr.toString file.ISA.WordSize (startAddr + size - uint64 1))
          normalizeEmpty s.Name
          HexString.ofUInt64 (uint64 s.VirtualSize)
          HexString.ofUInt64 (uint64 s.VirtualAddress)
          HexString.ofUInt64 (uint64 s.SizeOfRawData)
          HexString.ofUInt64 (uint64 s.PointerToRawData)
          HexString.ofUInt64 (uint64 s.PointerToRelocations)
          HexString.ofUInt64 (uint64 s.PointerToLineNumbers)
          s.NumberOfRelocations.ToString ()
          s.NumberOfLineNumbers.ToString ()
          HexString.ofUInt64 characteristics ])
      translateSectionChracteristics characteristics
      |> List.iter (fun str ->
        out.PrintRow (true, cfg, [ ""; ""; ""; ""; ""; ""; ""
                                   ""; ""; ""; ""; ""; str ])))
  else
    let cfg = [ LeftAligned 4; addrColumn; addrColumn; LeftAligned 24 ]
    out.PrintRow (true, cfg, [ "Num"; "Start"; "End"; "Name" ])
    out.PrintLine "  ---"
    pe.SectionHeaders
    |> Array.iteri (fun idx s ->
      let addr = uint64 s.VirtualAddress + file.BaseAddress
      out.PrintRow (true, cfg,
        [ String.wrapSqrdBracket (idx.ToString ())
          (Addr.toString file.ISA.WordSize addr)
          (Addr.toString file.ISA.WordSize (addr + uint64 s.VirtualSize - 1UL))
          normalizeEmpty s.Name ]))

let dumpSectionDetails (secname: string) (file: PEBinFile) =
  let idx =
    Array.tryFindIndex (fun (s: SectionHeader) ->
      s.Name = secname) file.PE.SectionHeaders
  match idx with
  | Some idx ->
    let section = file.PE.SectionHeaders[idx]
    let characteristics = uint64 section.SectionCharacteristics
    out.PrintTwoCols
      "Section number:"
      (String.wrapSqrdBracket (idx.ToString ()))
    out.PrintTwoCols
      "Section name:"
      section.Name
    out.PrintTwoCols
      "Virtual size:"
      (HexString.ofUInt64 (uint64 section.VirtualSize))
    out.PrintTwoCols
      "Virtual address:"
      (HexString.ofUInt64 (uint64 section.VirtualAddress))
    out.PrintTwoCols
      "Size of raw data:"
      (HexString.ofUInt64 (uint64 section.SizeOfRawData))
    out.PrintTwoCols
      "Pointer to raw data:"
      (HexString.ofUInt64 (uint64 section.PointerToRawData))
    out.PrintTwoCols
      "Pointer to relocations:"
      (HexString.ofUInt64 (uint64 section.PointerToRelocations))
    out.PrintTwoCols
      "Pointer to line numbers:"
      (HexString.ofUInt64 (uint64 section.PointerToLineNumbers))
    out.PrintTwoCols
      "Number of relocations:"
      (section.NumberOfRelocations.ToString ())
    out.PrintTwoCols
      "Number of line numbers:"
      (section.NumberOfLineNumbers.ToString ())
    out.PrintTwoCols
      "Characteristics:"
      (HexString.ofUInt64 characteristics)
    translateSectionChracteristics characteristics
    |> List.iter (fun str -> out.PrintTwoCols "" str)
  | None -> out.PrintTwoCols "" "Not found."

let printSymbolRow pe cfg vis flags addr name libName =
  out.PrintRow (true, cfg,
    [ vis
      flags
      Addr.toString (pe :> IBinFile).ISA.WordSize addr
      normalizeEmpty name
      libName ])

let printSymbolInfo (pe: PEBinFile) =
  let addrColumn = columnWidthOfAddr pe |> LeftAligned
  let cfg = [ LeftAligned 3; LeftAligned 10
              addrColumn; LeftAligned 50; LeftAligned 15 ]
  out.PrintRow (true, cfg, [ "S/D"; "Kind"; "Address"; "Name"; "Lib Name" ])
  out.PrintLine "  ---"
  for s in pe.PE.SymbolInfo.SymbolArray do
    printSymbolRow pe cfg "(s)" $"{s.Flags}" s.Address s.Name ""
  pe.PE.ImportMap
  |> Map.iter (fun rva imp ->
    let addr = pe.PE.BaseAddr + uint64 rva
    match imp with
    | PE.ImportByOrdinal (ord, dllname) ->
      printSymbolRow pe cfg "(d)" $"{ord}" addr $"#{ord}" dllname
    | PE.ImportByName (hint, fn, dllname) ->
      printSymbolRow pe cfg "(d)" $"{hint}" addr fn dllname
  )
  pe.PE.ExportMap
  |> Map.iter (fun addr names ->
    for name in names do
      let rva = int (addr - pe.PE.BaseAddr)
      let idx = pe.PE.FindSectionIdxFromRVA rva
      if idx = -1 then ()
      else
        let schr = pe.PE.SectionHeaders[idx].SectionCharacteristics
        printSymbolRow pe cfg "(d)" $"{schr}" addr name ""
  )
  pe.PE.ForwardMap
  |> Map.iter (fun name (fwdBin, fwdFunc) ->
    printSymbolRow pe cfg "(d)" $"{fwdBin},{fwdFunc}" 0UL name ""
  )

let dumpSymbols _ (pe: PEBinFile) =
  printSymbolInfo pe

let dumpRelocs _ (pe: PEBinFile) =
  let addrColumn = columnWidthOfAddr pe |> LeftAligned
  let cfg = [ addrColumn; LeftAligned 50 ]
  out.PrintRow (true, cfg, [ "Address"; "Relocation Type" ])
  out.PrintLine " ---"
  for block in pe.PE.RelocBlocks do
    for entry in block.Entries do
      let addr = uint64 block.PageRVA + uint64 entry.Offset
      out.PrintRow (true, cfg, [
        Addr.toString (pe :> IBinFile).ISA.WordSize addr
        $"{entry.Type}"
      ])

let dumpFunctions _ (pe: PEBinFile) =
  let addrColumn = columnWidthOfAddr pe |> LeftAligned
  let cfg = [ addrColumn; LeftAligned 50 ]
  out.PrintRow (true, cfg, [ "Address"; "Function" ])
  out.PrintLine " ---"
  for addr in (pe :> IBinFile).GetFunctionAddresses () do
    match (pe :> IBinFile).TryFindFunctionName addr with
    | Ok name ->
      out.PrintRow (true, cfg, [
        Addr.toString (pe :> IBinFile).ISA.WordSize addr
        name
      ])
    | Error _ -> ()

let inline addrFromRVA baseAddr rva =
  uint64 rva + baseAddr

let dumpImports _ (file: PEBinFile) =
  let cfg = [ LeftAligned 50; LeftAligned 50; LeftAligned 20 ]
  out.PrintRow (true, cfg,
    [ "FunctionName"; "Lib Name"; "TableAddress" ])
  out.PrintLine "  ---"
  file.PE.ImportMap
  |> Map.iter (fun addr info ->
    match info with
    | PE.ImportInfo.ImportByOrdinal (ordinal, dllname) ->
      out.PrintRow (true, cfg,
        [ "#" + ordinal.ToString ()
          dllname
          HexString.ofUInt64 (addrFromRVA file.PE.BaseAddr addr) ])
    | PE.ImportInfo.ImportByName (_, fname, dllname) ->
      out.PrintRow (true, cfg,
        [ fname
          dllname
          HexString.ofUInt64 (addrFromRVA file.PE.BaseAddr addr) ]))

let dumpExports _ (file: PEBinFile) =
  let cfg = [ LeftAligned 45; LeftAligned 20 ]
  out.PrintRow (true, cfg, [ "FunctionName"; "TableAddress" ])
  out.PrintLine "  ---"
  file.PE.ExportMap
  |> Map.iter (fun addr names ->
    let rva = int (addr - file.PE.BaseAddr)
    match file.PE.FindSectionIdxFromRVA rva with
    | -1 -> ()
    | idx ->
      names
      |> List.iter (fun name ->
        out.PrintRow (true, cfg, [ name; HexString.ofUInt64 addr ])))
  out.PrintLine ""
  out.PrintRow (true, cfg, [ "FunctionName"; "ForwardName" ])
  out.PrintLine "  ---"
  file.PE.ForwardMap
  |> Map.iter (fun name (bin, func) ->
    out.PrintRow (true, cfg, [ name; bin + "!" + func ]))

let translateDllChracteristcs chars =
  let enumChars =
    System.Enum.GetValues (typeof<DllCharacteristics>)
    :?> DllCharacteristics []
    |> Array.toList
  let rec loop acc chars = function
    | [] -> List.rev acc
    | enumChar :: tail as all ->
      if uint64 enumChar &&& chars = uint64 enumChar then
        loop ((" - " + enumChar.ToString ()) :: acc) chars tail
      elif uint64 0x0080 &&& chars = uint64 0x0080 then
        loop (" - ForceIntegrity" :: acc) (chars ^^^ uint64 0x0080) all
      elif uint64 0x4000 &&& chars = uint64 0x4000 then
        loop (" - ControlFlowGuard" :: acc) (chars ^^^ uint64 0x4000) all
      else
        loop acc chars tail
  loop [] chars enumChars

let dumpOptionalHeader _ (file: PEBinFile) =
  let hdr = file.PE.PEHeaders.PEHeader
  let imageBase = hdr.ImageBase
  let sizeOfImage = uint64 hdr.SizeOfImage
  let entryPoint =
    HexString.ofUInt64 (imageBase + uint64 hdr.AddressOfEntryPoint)
  let startImage = HexString.ofUInt64 imageBase
  let endImage = HexString.ofUInt64 (imageBase + sizeOfImage - uint64 1)
  let exportDir = hdr.ExportTableDirectory
  let importDir = hdr.ImportTableDirectory
  let resourceDir = hdr.ResourceTableDirectory
  let exceptionDir = hdr.ExceptionTableDirectory
  let certificateDir = hdr.CertificateTableDirectory
  let baseRelocDir = hdr.BaseRelocationTableDirectory
  let debugDir = hdr.DebugTableDirectory
  let architectureDir = hdr.CopyrightTableDirectory
  let globalPtrDir = hdr.GlobalPointerTableDirectory
  let threadLoStorDir = hdr.ThreadLocalStorageTableDirectory
  let loadConfigDir = hdr.ThreadLocalStorageTableDirectory
  let boundImpDir = hdr.BoundImportTableDirectory
  let importAddrDir = hdr.ImportAddressTableDirectory
  let delayImpDir = hdr.DelayImportTableDirectory
  let comDescDir = hdr.CorHeaderTableDirectory
  out.PrintTwoCols
    "Magic:"
    (HexString.ofUInt64 (uint64 hdr.Magic)
    + String.wrapParen (hdr.Magic.ToString ()))
  out.PrintTwoCols
    "Linker version:"
    (hdr.MajorLinkerVersion.ToString ()
    + "." + hdr.MinorLinkerVersion.ToString ())
  out.PrintTwoCols
    "Size of code:"
    (HexString.ofUInt64 (uint64 hdr.SizeOfCode))
  out.PrintTwoCols
    "Size of initialized data:"
    (HexString.ofUInt64 (uint64 hdr.SizeOfInitializedData))
  out.PrintTwoCols
    "Size of uninitialized data:"
    (HexString.ofUInt64 (uint64 hdr.SizeOfUninitializedData))
  out.PrintTwoCols
    "Entry point:"
    entryPoint
  out.PrintTwoCols
    "Base of code:"
    (HexString.ofUInt64 (uint64 hdr.BaseOfCode))
  out.PrintTwoCols
    "Image base:"
    (HexString.ofUInt64 imageBase
    + String.wrapParen (startImage + " to " + endImage))
  out.PrintTwoCols
    "Section alignment:"
    (HexString.ofUInt64 (uint64 hdr.SectionAlignment))
  out.PrintTwoCols
    "File Alignment:"
    (HexString.ofUInt64 (uint64 hdr.FileAlignment))
  out.PrintTwoCols
    "Operating system version:"
    (hdr.MajorOperatingSystemVersion.ToString ()
     + "." + hdr.MinorOperatingSystemVersion.ToString ())
  out.PrintTwoCols
    "Image version:"
    (hdr.MajorImageVersion.ToString ()
     + "." + hdr.MinorImageVersion.ToString ())
  out.PrintTwoCols
    "Subsystem version:"
    (hdr.MajorSubsystemVersion.ToString ()
     + "." + hdr.MinorSubsystemVersion.ToString ())
  out.PrintTwoCols
    "Size of image:"
    (HexString.ofUInt64 sizeOfImage)
  out.PrintTwoCols
    "Size of headers:"
    (HexString.ofUInt64 (uint64 hdr.SizeOfHeaders))
  out.PrintTwoCols
    "Checksum:"
    (HexString.ofUInt64 (uint64 hdr.CheckSum))
  out.PrintTwoCols
    "Subsystem:"
    (HexString.ofUInt64 (uint64 hdr.Subsystem)
    + String.wrapParen (hdr.Subsystem.ToString ()))
  out.PrintTwoCols
    "DLL characteristics:"
    (HexString.ofUInt64 (uint64 hdr.DllCharacteristics))
  translateDllChracteristcs (uint64 hdr.DllCharacteristics)
  |> List.iter (fun str -> out.PrintTwoCols "" str)
  out.PrintTwoCols
    "Size of stack reserve:"
    (HexString.ofUInt64 (uint64 hdr.SizeOfStackReserve))
  out.PrintTwoCols
    "Size of stack commit:"
    (HexString.ofUInt64 (uint64 hdr.SizeOfStackCommit))
  out.PrintTwoCols
    "Size of heap reserve:"
    (HexString.ofUInt64 (uint64 hdr.SizeOfHeapReserve))
  out.PrintTwoCols
    "Size of heap commit:"
    (HexString.ofUInt64 (uint64 hdr.SizeOfHeapCommit))
  out.PrintTwoCols
    "Loader flags (reserved):"
    "0x0"
  out.PrintTwoCols
    "Number of directories:"
    (hdr.NumberOfRvaAndSizes.ToString ())
  out.PrintTwoCols
    "RVA[size] of Export Table Directory:"
    (HexString.ofUInt64 (uint64 exportDir.RelativeVirtualAddress)
    + String.wrapSqrdBracket (HexString.ofUInt64 (uint64 exportDir.Size)))
  out.PrintTwoCols
    "RVA[size] of Import Table Directory:"
    (HexString.ofUInt64 (uint64 importDir.RelativeVirtualAddress)
    + String.wrapSqrdBracket (HexString.ofUInt64 (uint64 importDir.Size)))
  out.PrintTwoCols
    "RVA[size] of Resource Table Directory:"
    (HexString.ofUInt64 (uint64 resourceDir.RelativeVirtualAddress)
    + String.wrapSqrdBracket (HexString.ofUInt64 (uint64 resourceDir.Size)))
  out.PrintTwoCols
    "RVA[size] of Exception Table Directory:"
    (HexString.ofUInt64 (uint64 exceptionDir.RelativeVirtualAddress)
    + String.wrapSqrdBracket (HexString.ofUInt64 (uint64 exceptionDir.Size)))
  out.PrintTwoCols
    "RVA[size] of Certificate Table Directory:"
    (HexString.ofUInt64 (uint64 certificateDir.RelativeVirtualAddress)
    + String.wrapSqrdBracket (HexString.ofUInt64 (uint64 certificateDir.Size)))
  out.PrintTwoCols
    "RVA[size] of Base Relocation Table Directory:"
    (HexString.ofUInt64 (uint64 baseRelocDir.RelativeVirtualAddress)
    + String.wrapSqrdBracket (HexString.ofUInt64 (uint64 baseRelocDir.Size)))
  out.PrintTwoCols
    "RVA[size] of Debug Table Directory:"
    (HexString.ofUInt64 (uint64 debugDir.RelativeVirtualAddress)
    + String.wrapSqrdBracket (HexString.ofUInt64 (uint64 debugDir.Size)))
  out.PrintTwoCols
    "RVA[size] of Architecture Table Directory:"
    (HexString.ofUInt64 (uint64 architectureDir.RelativeVirtualAddress)
    + String.wrapSqrdBracket (HexString.ofUInt64 (uint64 architectureDir.Size)))
  out.PrintTwoCols
    "RVA[size] of Global Pointer Table Directory:"
    (HexString.ofUInt64 (uint64 globalPtrDir.RelativeVirtualAddress)
    + String.wrapSqrdBracket (HexString.ofUInt64 (uint64 globalPtrDir.Size)))
  out.PrintTwoCols
    "RVA[size] of Thread Storage Table Directory:"
    (HexString.ofUInt64 (uint64 threadLoStorDir.RelativeVirtualAddress)
    + String.wrapSqrdBracket (HexString.ofUInt64 (uint64 threadLoStorDir.Size)))
  out.PrintTwoCols
    "RVA[size] of Load Configuration Table Directory:"
    (HexString.ofUInt64 (uint64 loadConfigDir.RelativeVirtualAddress)
    + String.wrapSqrdBracket (HexString.ofUInt64 (uint64 loadConfigDir.Size)))
  out.PrintTwoCols
    "RVA[size] of Bound Import Table Directory:"
    (HexString.ofUInt64 (uint64 boundImpDir.RelativeVirtualAddress)
    + String.wrapSqrdBracket (HexString.ofUInt64 (uint64 boundImpDir.Size)))
  out.PrintTwoCols
    "RVA[size] of Import Address Table Directory:"
    (HexString.ofUInt64 (uint64 importAddrDir.RelativeVirtualAddress)
    + String.wrapSqrdBracket (HexString.ofUInt64 (uint64 importAddrDir.Size)))
  out.PrintTwoCols
    "RVA[size] of Delay Import Table Directory:"
    (HexString.ofUInt64 (uint64 delayImpDir.RelativeVirtualAddress)
    + String.wrapSqrdBracket (HexString.ofUInt64 (uint64 delayImpDir.Size)))
  out.PrintTwoCols
    "RVA[size] of COM Descriptor Table Directory:"
    (HexString.ofUInt64 (uint64 comDescDir.RelativeVirtualAddress)
    + String.wrapSqrdBracket (HexString.ofUInt64 (uint64 comDescDir.Size)))
  out.PrintTwoCols
    "RVA[size] of Reserved Directory:"
    "0x0[0x0]"

let translateCorFlags flags =
  let enumFlags =
    System.Enum.GetValues (typeof<CorFlags>)
    :?> CorFlags []
    |> Array.toList
  let rec loop acc flags = function
    | [] -> List.rev acc
    | enumFlag :: tail ->
      if uint64 enumFlag &&& flags = uint64 enumFlag then
        loop ((" - " + enumFlag.ToString ()) :: acc) flags tail
      else
        loop acc flags tail
  loop [] flags enumFlags

let dumpCLRHeader _ (file: PEBinFile) =
  let hdr = file.PE.PEHeaders.CorHeader
  if isNull hdr then
    out.PrintTwoCols "" "Not found."
  else
    let metaDataDir = hdr.MetadataDirectory
    let resourcesDir = hdr.ResourcesDirectory
    let strongNameSigDir = hdr.StrongNameSignatureDirectory
    let codeMgrTblDir = hdr.CodeManagerTableDirectory
    let vTableFixups = hdr.VtableFixupsDirectory
    let exportAddrTblJmps = hdr.ExportAddressTableJumpsDirectory
    let managedNativeHdr = hdr.ManagedNativeHeaderDirectory
    out.PrintTwoCols
      "Runtime version:"
      (hdr.MajorRuntimeVersion.ToString ()
      + "." + hdr.MinorRuntimeVersion.ToString ())
    out.PrintTwoCols
      "RVA[size] of Meta Data Directory:"
      (HexString.ofUInt64 (uint64 metaDataDir.RelativeVirtualAddress)
      + String.wrapSqrdBracket (HexString.ofUInt64 (uint64 metaDataDir.Size)))
    out.PrintTwoCols
      "Flags:"
      (HexString.ofUInt64 (uint64 hdr.Flags))
    translateCorFlags (uint64 hdr.Flags)
    |> List.iter (fun str -> out.PrintTwoCols "" str)
    out.PrintTwoCols
      "RVA[size] of Resources Directory:"
      (HexString.ofUInt64 (uint64 resourcesDir.RelativeVirtualAddress)
      + String.wrapSqrdBracket (HexString.ofUInt64 (uint64 resourcesDir.Size)))
    out.PrintTwoCols
      "RVA[size] of Strong Name Signature Directory:"
      (HexString.ofUInt64 (uint64 strongNameSigDir.RelativeVirtualAddress)
      + String.wrapSqrdBracket (HexString.ofInt32 strongNameSigDir.Size))
    out.PrintTwoCols
      "RVA[size] of Code Manager Table Directory:"
      (HexString.ofUInt64 (uint64 codeMgrTblDir.RelativeVirtualAddress)
      + String.wrapSqrdBracket (HexString.ofUInt64 (uint64 codeMgrTblDir.Size)))
    out.PrintTwoCols
      "RVA[size] of VTable Fixups Directory:"
      (HexString.ofUInt64 (uint64 vTableFixups.RelativeVirtualAddress)
      + String.wrapSqrdBracket (HexString.ofUInt64 (uint64 vTableFixups.Size)))
    out.PrintTwoCols
      "RVA[size] of Export Address Table Jumps Directory:"
      (HexString.ofUInt64 (uint64 exportAddrTblJmps.RelativeVirtualAddress)
      + String.wrapSqrdBracket
          (HexString.ofUInt64 (uint64 exportAddrTblJmps.Size)))
    out.PrintTwoCols
      "RVA[size] of Managed Native Header Directory:"
      (HexString.ofUInt64 (uint64 managedNativeHdr.RelativeVirtualAddress)
      + String.wrapSqrdBracket (HexString.ofInt32 managedNativeHdr.Size))

let dumpDependencies _ (file: IBinFile) =
  file.GetLinkageTableEntries ()
  |> Seq.map (fun e -> e.LibraryName)
  |> Set.ofSeq
  |> Set.iter (fun s -> out.PrintTwoCols "" s)
