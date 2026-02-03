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

let badAccess _ _ = raise InvalidFileFormatException

let translateChracteristics chars =
  let enumChars =
    System.Enum.GetValues(typeof<Characteristics>)
    :?> Characteristics []
    |> Array.toList
  let rec loop acc chars = function
    | [] -> List.rev acc
    | enumChar :: tail ->
      if uint64 enumChar &&& chars = uint64 enumChar then
        loop ((" - " + enumChar.ToString()) :: acc) chars tail
      else
        loop acc chars tail
  loop [] chars enumChars

let dumpFileHeader _ (file: PEBinFile) =
  let hdr = file.PEHeaders.CoffHeader
  Terminal.Out
  <== TableConfig.DefaultTwoColumn
  <== [ "Machine:"
        HexString.ofUInt64 (uint64 hdr.Machine)
        + String.wrapParen (hdr.Machine.ToString()) ]
  <== [ "Number of sections:"; hdr.NumberOfSections.ToString() ]
  <== [ "Time date stamp:"; hdr.TimeDateStamp.ToString() ]
  <== [ "Pointer to symbol table:"
        HexString.ofUInt64 (uint64 hdr.PointerToSymbolTable) ]
  <== [ "Size of optional header:"
        HexString.ofUInt64 (uint64 hdr.SizeOfOptionalHeader) ]
  <=/ [ "Characteristics:"
        HexString.ofUInt64 (uint64 hdr.Characteristics) ]
  translateChracteristics (uint64 hdr.Characteristics)
  |> List.iter (fun str -> Terminal.Out <=/ [ ""; str ])

let translateSectionChracteristics chars =
  let enumChars =
    System.Enum.GetValues(typeof<SectionCharacteristics>)
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
          loop ((" - " + enumChar.ToString()) :: acc) chars t
        else
          loop acc chars t
    loop [] chars enumChars

let dumpSectionHeaders (opts: FileViewerOpts) (pe: PEBinFile) =
  let addrColumn = columnWidthOfAddr pe |> LeftAligned
  let file = pe :> IBinFile
  if opts.Verbose then
    Terminal.Out
    <== [ LeftAligned 4
          addrColumn
          addrColumn
          LeftAligned 24
          LeftAligned 8
          LeftAligned 8
          LeftAligned 8
          LeftAligned 8
          LeftAligned 8
          LeftAligned 8
          LeftAligned 8
          LeftAligned 8
          LeftAligned 8 ]
    <== [ "Num"
          "Start"
          "End"
          "Name"
          "VirtSize"
          "VirtAddr"
          "RawSize"
          "RawPtr"
          "RelocPtr"
          "LineNPtr"
          "RelocNum"
          "LineNNum"
          "Characteristics" ]
    <=/ "  ---"
    pe.SectionHeaders
    |> Array.iteri (fun idx s ->
      let startAddr = pe.BaseAddress + uint64 s.VirtualAddress
      let size =
        uint64 (if s.VirtualSize = 0 then s.SizeOfRawData else s.VirtualSize)
      let characteristics = uint64 s.SectionCharacteristics
      Terminal.Out
      <=/ [ String.wrapSqrdBracket (idx.ToString())
            Addr.toString file.ISA.WordSize startAddr
            Addr.toString file.ISA.WordSize (startAddr + size - uint64 1)
            normalizeEmpty s.Name
            HexString.ofUInt64 (uint64 s.VirtualSize)
            HexString.ofUInt64 (uint64 s.VirtualAddress)
            HexString.ofUInt64 (uint64 s.SizeOfRawData)
            HexString.ofUInt64 (uint64 s.PointerToRawData)
            HexString.ofUInt64 (uint64 s.PointerToRelocations)
            HexString.ofUInt64 (uint64 s.PointerToLineNumbers)
            s.NumberOfRelocations.ToString()
            s.NumberOfLineNumbers.ToString()
            HexString.ofUInt64 characteristics ]
      translateSectionChracteristics characteristics
      |> List.iter (fun str ->
        Terminal.Out
        <=/ [ ""; ""; ""; ""; ""; ""; ""; ""; ""; ""; ""; ""; str ])
    )
  else
    Terminal.Out
    <== [ LeftAligned 4; addrColumn; addrColumn; LeftAligned 24 ]
    <== [ "Num"; "Start"; "End"; "Name" ]
    <=/ "  ---"
    pe.SectionHeaders
    |> Array.iteri (fun idx s ->
      let addr = uint64 s.VirtualAddress + file.BaseAddress
      Terminal.Out
      <=/ [ String.wrapSqrdBracket (idx.ToString())
            Addr.toString file.ISA.WordSize addr
            Addr.toString file.ISA.WordSize (addr + uint64 s.VirtualSize - 1UL)
            normalizeEmpty s.Name ]
    )

let dumpSectionDetails (secname: string) (file: PEBinFile) =
  let idx =
    Array.tryFindIndex (fun (s: SectionHeader) ->
      s.Name = secname) file.SectionHeaders
  match idx with
  | Some idx ->
    let section = file.SectionHeaders[idx]
    let characteristics = uint64 section.SectionCharacteristics
    Terminal.Out
    <== TableConfig.DefaultTwoColumn
    <== [ "Section number:"; String.wrapSqrdBracket (idx.ToString()) ]
    <== [ "Section name:"; section.Name ]
    <== [ "Virtual size:"
          HexString.ofUInt64 (uint64 section.VirtualSize) ]
    <== [ "Virtual address:"
          HexString.ofUInt64 (uint64 section.VirtualAddress) ]
    <== [ "Size of raw data:"
          HexString.ofUInt64 (uint64 section.SizeOfRawData) ]
    <== [ "Pointer to raw data:"
          HexString.ofUInt64 (uint64 section.PointerToRawData) ]
    <== [ "Pointer to relocations:"
          HexString.ofUInt64 (uint64 section.PointerToRelocations) ]
    <== [ "Pointer to line numbers:"
          HexString.ofUInt64 (uint64 section.PointerToLineNumbers) ]
    <== [ "Number of relocations:"
          section.NumberOfRelocations.ToString() ]
    <== [ "Number of line numbers:"
          section.NumberOfLineNumbers.ToString() ]
    <=/ [ "Characteristics:"; HexString.ofUInt64 characteristics ]
    translateSectionChracteristics characteristics
    |> List.iter (fun str -> Terminal.Out <=/ [ ""; str ])
  | None ->
    Terminal.Out <=/ [ ""; "Not found." ]

let printSymbolRow pe vis flags addr name libName =
  Terminal.Out
  <=/ [ vis
        flags
        Addr.toString (pe :> IBinFile).ISA.WordSize addr
        normalizeEmpty name
        libName ]

let printSymbolInfo (pe: PEBinFile) =
  let addrColumn = columnWidthOfAddr pe |> LeftAligned
  Terminal.Out
  <== [ LeftAligned 3
        LeftAligned 10
        addrColumn
        LeftAligned 50
        LeftAligned 15 ]
  <== [ "S/D"; "Kind"; "Address"; "Name"; "Lib Name" ]
  <=/ "  ---"
  for s in pe.Symbols.SymbolArray do
    printSymbolRow pe "(s)" "" s.Address s.Name ""
  pe.ImportedSymbols
  |> Map.iter (fun rva imp ->
    let addr = pe.BaseAddress + uint64 rva
    match imp with
    | PE.ByOrdinal(ord, dllname) ->
      printSymbolRow pe "(d)" $"{ord}" addr $"#{ord}" dllname
    | PE.ByName(hint, fn, dllname) ->
      printSymbolRow pe "(d)" $"{hint}" addr fn dllname
  )
  pe.ExportedSymbols.Exports
  |> Map.iter (fun addr names ->
    for name in names do
      let rva = int (addr - pe.BaseAddress)
      let idx = pe.FindSectionIdxFromRVA rva
      if idx = -1 then ()
      else
        let schr = pe.SectionHeaders[idx].SectionCharacteristics
        printSymbolRow pe "(d)" $"{schr}" addr name ""
  )
  pe.ExportedSymbols.Forwards
  |> Map.iter (fun name (fwdBin, fwdFunc) ->
    printSymbolRow pe "(d)" $"{fwdBin},{fwdFunc}" 0UL name ""
  )

let dumpSymbols _ (pe: PEBinFile) = printSymbolInfo pe

let dumpRelocs _ (pe: PEBinFile) =
  let addrColumn = columnWidthOfAddr pe |> LeftAligned
  Terminal.Out
  <== [ addrColumn; LeftAligned 50 ]
  <== [ "Address"; "Relocation Type" ]
  <=/ " ---"
  for block in pe.RelocBlocks do
    for entry in block.Entries do
      let addr = uint64 block.PageRVA + uint64 entry.Offset
      Terminal.Out
      <=/ [ Addr.toString (pe :> IBinFile).ISA.WordSize addr
            $"{entry.Type}" ]

let dumpFunctions _ (pe: PEBinFile) =
  let addrColumn = columnWidthOfAddr pe |> LeftAligned
  Terminal.Out
  <== [ addrColumn; LeftAligned 50 ]
  <== [ "Address"; "Function" ]
  <=/ " ---"
  for addr in (pe :> IBinFile).GetFunctionAddresses() do
    match (pe :> IBinFile).TryFindName addr with
    | Ok name ->
      Terminal.Out
      <=/ [ Addr.toString (pe :> IBinFile).ISA.WordSize addr; name ]
    | Error _ -> ()

let inline addrFromRVA baseAddr rva = uint64 rva + baseAddr

let dumpImports _ (file: PEBinFile) =
  Terminal.Out
  <== [ LeftAligned 50; LeftAligned 50; LeftAligned 20 ]
  <== [ "FunctionName"; "Lib Name"; "TableAddress" ]
  <=/ "  ---"
  file.ImportedSymbols
  |> Map.iter (fun addr info ->
    match info with
    | PE.ImportedSymbol.ByOrdinal(ordinal, dllname) ->
      Terminal.Out
      <=/ [ "#" + ordinal.ToString()
            dllname
            HexString.ofUInt64 (addrFromRVA file.BaseAddress addr) ]
    | PE.ImportedSymbol.ByName(_, fname, dllname) ->
      Terminal.Out
      <=/ [ fname
            dllname
            HexString.ofUInt64 (addrFromRVA file.BaseAddress addr) ])

let dumpExports _ (file: PEBinFile) =
  Terminal.Out
  <== [ LeftAligned 45; LeftAligned 20 ]
  <== [ "FunctionName"; "TableAddress" ]
  <=/ "  ---"
  file.ExportedSymbols.Exports
  |> Map.iter (fun addr names ->
    let rva = int (addr - file.BaseAddress)
    match file.FindSectionIdxFromRVA rva with
    | -1 -> ()
    | idx ->
      names
      |> List.iter (fun name ->
        Terminal.Out <=/ [ name; HexString.ofUInt64 addr ]))
  Terminal.Out.PrintLine()
  Terminal.Out
  <== [ "FunctionName"; "ForwardName" ]
  <=/ "  ---"
  file.ExportedSymbols.Forwards
  |> Map.iter (fun name (bin, func) ->
    Terminal.Out <=/ [ name; bin + "!" + func ])

let translateDllChracteristcs chars =
  let enumChars =
    System.Enum.GetValues(typeof<DllCharacteristics>)
    :?> DllCharacteristics []
    |> Array.toList
  let rec loop acc chars = function
    | [] -> List.rev acc
    | enumChar :: tail as all ->
      if uint64 enumChar &&& chars = uint64 enumChar then
        loop ((" - " + enumChar.ToString()) :: acc) chars tail
      elif uint64 0x0080 &&& chars = uint64 0x0080 then
        loop (" - ForceIntegrity" :: acc) (chars ^^^ uint64 0x0080) all
      elif uint64 0x4000 &&& chars = uint64 0x4000 then
        loop (" - ControlFlowGuard" :: acc) (chars ^^^ uint64 0x4000) all
      else
        loop acc chars tail
  loop [] chars enumChars

let dumpOptionalHeader _ (file: PEBinFile) =
  let hdr = file.PEHeaders.PEHeader
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
  Terminal.Out
  <== TableConfig.DefaultTwoColumn
  <== [ "Magic:"
        HexString.ofUInt64 (uint64 hdr.Magic)
        + String.wrapParen (hdr.Magic.ToString()) ]
  <== [ "Linker version:"
        hdr.MajorLinkerVersion.ToString()
        + "."
        + hdr.MinorLinkerVersion.ToString() ]
  <== [ "Size of code:"
        HexString.ofUInt64 (uint64 hdr.SizeOfCode) ]
  <== [ "Size of initialized data:"
        HexString.ofUInt64 (uint64 hdr.SizeOfInitializedData) ]
  <== [ "Size of uninitialized data:"
        HexString.ofUInt64 (uint64 hdr.SizeOfUninitializedData) ]
  <== [ "Entry point:"; entryPoint ]
  <== [ "Base of code:"; HexString.ofUInt64 (uint64 hdr.BaseOfCode) ]
  <== [ "Image base:"
        HexString.ofUInt64 imageBase
        + String.wrapParen (startImage + " to " + endImage) ]
  <== [ "Section alignment:"
        HexString.ofUInt64 (uint64 hdr.SectionAlignment) ]
  <== [ "File Alignment:"
        HexString.ofUInt64 (uint64 hdr.FileAlignment) ]
  <== [ "Operating system version:"
        hdr.MajorOperatingSystemVersion.ToString()
        + "." + hdr.MinorOperatingSystemVersion.ToString() ]
  <== [ "Image version:"
        hdr.MajorImageVersion.ToString()
        + "."
        + hdr.MinorImageVersion.ToString() ]
  <== [ "Subsystem version:"
        hdr.MajorSubsystemVersion.ToString()
        + "."
        + hdr.MinorSubsystemVersion.ToString() ]
  <== [ "Size of image:"; HexString.ofUInt64 sizeOfImage ]
  <== [ "Size of headers:"; HexString.ofUInt64 (uint64 hdr.SizeOfHeaders) ]
  <== [ "Checksum:"; HexString.ofUInt64 (uint64 hdr.CheckSum) ]
  <== [ "Subsystem:"
        HexString.ofUInt64 (uint64 hdr.Subsystem)
        + String.wrapParen (hdr.Subsystem.ToString()) ]
  <=/ [ "DLL characteristics:"
        HexString.ofUInt64 (uint64 hdr.DllCharacteristics) ]
  translateDllChracteristcs (uint64 hdr.DllCharacteristics)
  |> List.iter (fun str -> Terminal.Out <=/ [ ""; str ])
  Terminal.Out
  <== [ "Size of stack reserve:"
        HexString.ofUInt64 (uint64 hdr.SizeOfStackReserve) ]
  <== [ "Size of stack commit:"
        HexString.ofUInt64 (uint64 hdr.SizeOfStackCommit) ]
  <== [ "Size of heap reserve:"
        HexString.ofUInt64 (uint64 hdr.SizeOfHeapReserve) ]
  <== [ "Size of heap commit:"
        HexString.ofUInt64 (uint64 hdr.SizeOfHeapCommit) ]
  <== [ "Loader flags (reserved):"; "0x0" ]
  <== [ "Number of directories:"; hdr.NumberOfRvaAndSizes.ToString() ]
  <== [ "RVA[size] of Export Table Directory:"
        HexString.ofUInt64 (uint64 exportDir.RelativeVirtualAddress)
        + String.wrapSqrdBracket (HexString.ofUInt64 (uint64 exportDir.Size)) ]
  <== [ "RVA[size] of Import Table Directory:"
        HexString.ofUInt64 (uint64 importDir.RelativeVirtualAddress)
        + String.wrapSqrdBracket (HexString.ofUInt64 (uint64 importDir.Size)) ]
  <== [ "RVA[size] of Resource Table Directory:"
        HexString.ofUInt64 (uint64 resourceDir.RelativeVirtualAddress)
        + String.wrapSqrdBracket
            (HexString.ofUInt64 (uint64 resourceDir.Size)) ]
  <== [ "RVA[size] of Exception Table Directory:"
        HexString.ofUInt64 (uint64 exceptionDir.RelativeVirtualAddress)
        + String.wrapSqrdBracket
            (HexString.ofUInt64 (uint64 exceptionDir.Size)) ]
  <== [ "RVA[size] of Certificate Table Directory:"
        HexString.ofUInt64 (uint64 certificateDir.RelativeVirtualAddress)
        + String.wrapSqrdBracket
            (HexString.ofUInt64 (uint64 certificateDir.Size)) ]
  <== [ "RVA[size] of Base Relocation Table Directory:"
        HexString.ofUInt64 (uint64 baseRelocDir.RelativeVirtualAddress)
        + String.wrapSqrdBracket
            (HexString.ofUInt64 (uint64 baseRelocDir.Size)) ]
  <== [ "RVA[size] of Debug Table Directory:"
        HexString.ofUInt64 (uint64 debugDir.RelativeVirtualAddress)
        + String.wrapSqrdBracket (HexString.ofUInt64 (uint64 debugDir.Size)) ]
  <== [ "RVA[size] of Architecture Table Directory:"
        HexString.ofUInt64 (uint64 architectureDir.RelativeVirtualAddress)
        + String.wrapSqrdBracket
            (HexString.ofUInt64 (uint64 architectureDir.Size)) ]
  <== [ "RVA[size] of Global Pointer Table Directory:"
        HexString.ofUInt64 (uint64 globalPtrDir.RelativeVirtualAddress)
        + String.wrapSqrdBracket
            (HexString.ofUInt64 (uint64 globalPtrDir.Size)) ]
  <== [ "RVA[size] of Thread Storage Table Directory:"
        HexString.ofUInt64 (uint64 threadLoStorDir.RelativeVirtualAddress)
        + String.wrapSqrdBracket
            (HexString.ofUInt64 (uint64 threadLoStorDir.Size)) ]
  <== [ "RVA[size] of Load Configuration Table Directory:"
        HexString.ofUInt64 (uint64 loadConfigDir.RelativeVirtualAddress)
        + String.wrapSqrdBracket
            (HexString.ofUInt64 (uint64 loadConfigDir.Size)) ]
  <== [ "RVA[size] of Bound Import Table Directory:"
        HexString.ofUInt64 (uint64 boundImpDir.RelativeVirtualAddress)
        + String.wrapSqrdBracket
            (HexString.ofUInt64 (uint64 boundImpDir.Size)) ]
  <== [ "RVA[size] of Import Address Table Directory:"
        HexString.ofUInt64 (uint64 importAddrDir.RelativeVirtualAddress)
        + String.wrapSqrdBracket
            (HexString.ofUInt64 (uint64 importAddrDir.Size)) ]
  <== [ "RVA[size] of Delay Import Table Directory:"
        HexString.ofUInt64 (uint64 delayImpDir.RelativeVirtualAddress)
        + String.wrapSqrdBracket
            (HexString.ofUInt64 (uint64 delayImpDir.Size)) ]
  <== [ "RVA[size] of COM Descriptor Table Directory:"
        HexString.ofUInt64 (uint64 comDescDir.RelativeVirtualAddress)
        + String.wrapSqrdBracket
            (HexString.ofUInt64 (uint64 comDescDir.Size)) ]
  <=/ [ "RVA[size] of Reserved Directory:"; "0x0[0x0]" ]

let translateCorFlags flags =
  let enumFlags =
    System.Enum.GetValues(typeof<CorFlags>)
    :?> CorFlags []
    |> Array.toList
  let rec loop acc flags = function
    | [] -> List.rev acc
    | enumFlag :: tail ->
      if uint64 enumFlag &&& flags = uint64 enumFlag then
        loop ((" - " + enumFlag.ToString()) :: acc) flags tail
      else
        loop acc flags tail
  loop [] flags enumFlags

let dumpCLRHeader _ (file: PEBinFile) =
  let hdr = file.PEHeaders.CorHeader
  if isNull hdr then
    Terminal.Out
    <== TableConfig.DefaultTwoColumn
    <=/ [ ""; "Not found." ]
  else
    let metaDataDir = hdr.MetadataDirectory
    let resourcesDir = hdr.ResourcesDirectory
    let strongNameSigDir = hdr.StrongNameSignatureDirectory
    let codeMgrTblDir = hdr.CodeManagerTableDirectory
    let vTableFixups = hdr.VtableFixupsDirectory
    let exportAddrTblJmps = hdr.ExportAddressTableJumpsDirectory
    let managedNativeHdr = hdr.ManagedNativeHeaderDirectory
    Terminal.Out
    <== TableConfig.DefaultTwoColumn
    <== [ "Runtime version:"
          hdr.MajorRuntimeVersion.ToString()
          + "." + hdr.MinorRuntimeVersion.ToString() ]
    <== [ "RVA[size] of Meta Data Directory:"
          HexString.ofUInt64 (uint64 metaDataDir.RelativeVirtualAddress)
          + String.wrapSqrdBracket
              (HexString.ofUInt64 (uint64 metaDataDir.Size)) ]
    <=/ [ "Flags:"; HexString.ofUInt64 (uint64 hdr.Flags) ]
    translateCorFlags (uint64 hdr.Flags)
    |> List.iter (fun str -> Terminal.Out <=/ [ ""; str ])
    Terminal.Out
    <== [ "RVA[size] of Resources Directory:"
          HexString.ofUInt64 (uint64 resourcesDir.RelativeVirtualAddress)
          + String.wrapSqrdBracket
              (HexString.ofUInt64 (uint64 resourcesDir.Size)) ]
    <== [ "RVA[size] of Strong Name Signature Directory:"
          HexString.ofUInt64 (uint64 strongNameSigDir.RelativeVirtualAddress)
          + String.wrapSqrdBracket
              (HexString.ofInt32 strongNameSigDir.Size) ]
    <== [ "RVA[size] of Code Manager Table Directory:"
          HexString.ofUInt64 (uint64 codeMgrTblDir.RelativeVirtualAddress)
          + String.wrapSqrdBracket
              (HexString.ofUInt64 (uint64 codeMgrTblDir.Size)) ]
    <== [ "RVA[size] of VTable Fixups Directory:"
          HexString.ofUInt64 (uint64 vTableFixups.RelativeVirtualAddress)
          + String.wrapSqrdBracket
              (HexString.ofUInt64 (uint64 vTableFixups.Size)) ]
    <== [ "RVA[size] of Export Address Table Jumps Directory:"
          HexString.ofUInt64 (uint64 exportAddrTblJmps.RelativeVirtualAddress)
          + String.wrapSqrdBracket
              (HexString.ofUInt64 (uint64 exportAddrTblJmps.Size)) ]
    <=/ [ "RVA[size] of Managed Native Header Directory:"
          HexString.ofUInt64 (uint64 managedNativeHdr.RelativeVirtualAddress)
          + String.wrapSqrdBracket (HexString.ofInt32 managedNativeHdr.Size) ]

let dumpDependencies _ (file: IBinFile) =
  file.GetLinkageTableEntries()
  |> Seq.map (fun e -> e.LibraryName)
  |> Set.ofSeq
  |> Set.iter (fun s -> Terminal.Out <=/ [ ""; s ])
