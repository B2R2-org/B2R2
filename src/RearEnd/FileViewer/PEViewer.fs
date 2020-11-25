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

open B2R2
open B2R2.FrontEnd.BinFile
open B2R2.RearEnd
open B2R2.RearEnd.StringUtils
open B2R2.RearEnd.FileViewer.Helper
open System.Reflection.PortableExecutable

let badAccess _ _ =
  raise InvalidFileTypeException

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

let dumpFileHeader _ (fi: PEFileInfo) =
  let hdr = fi.PE.PEHeaders.CoffHeader
  Printer.printTwoCols
    "Machine:"
    (u64ToHexString (uint64 hdr.Machine) + wrapParen (hdr.Machine.ToString ()))
  Printer.printTwoCols
    "Number of sections:"
    (hdr.NumberOfSections.ToString ())
  Printer.printTwoCols
    "Time date stamp:"
    (hdr.TimeDateStamp.ToString ())
  Printer.printTwoCols
    "Pointer to symbol table:"
    (u64ToHexString (uint64 hdr.PointerToSymbolTable))
  Printer.printTwoCols
    "Size of optional header:"
    (u64ToHexString (uint64 hdr.SizeOfOptionalHeader))
  Printer.printTwoCols
    "Characteristics:"
    (u64ToHexString (uint64 hdr.Characteristics))
  translateChracteristics (uint64 hdr.Characteristics)
  |> List.iter (fun str -> Printer.printTwoCols "" str)

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
          && not (uint64 enumChar = uint64 0) then
          loop ((" - " + enumChar.ToString ()) :: acc) chars t
        else
          loop acc chars t
    loop [] chars enumChars

let dumpSectionHeaders (opts: FileViewerOpts) (fi: PEFileInfo) =
  let addrColumn = columnWidthOfAddr fi |> LeftAligned
  if opts.Verbose then
    let cfg = [ LeftAligned 4; addrColumn; addrColumn; LeftAligned 24
                LeftAligned 8; LeftAligned 8; LeftAligned 8; LeftAligned 8
                LeftAligned 8; LeftAligned 8; LeftAligned 8; LeftAligned 8
                LeftAligned 8 ]
    Printer.printrow (true, cfg,
      [ "Num"; "Start"; "End"; "Name"
        "VirtSize"; "VirtAddr"; "RawSize"; "RawPtr"
        "RelocPtr"; "LineNPtr"; "RelocNum"; "LineNNum"
        "Characteristics" ])
    Printer.println "  ---"
    fi.PE.SectionHeaders
    |> Array.iteri (fun idx s ->
      let startAddr = fi.PE.BaseAddr + uint64 s.VirtualAddress
      let size =
        uint64 (if s.VirtualSize = 0 then s.SizeOfRawData else s.VirtualSize)
      let characteristics = uint64 s.SectionCharacteristics
      Printer.printrow (true, cfg,
        [ wrapSqrdBrac (idx.ToString ())
          (addrToString fi.WordSize startAddr)
          (addrToString fi.WordSize (startAddr + size - uint64 1))
          normalizeEmpty s.Name
          u64ToHexString (uint64 s.VirtualSize)
          u64ToHexString (uint64 s.VirtualAddress)
          u64ToHexString (uint64 s.SizeOfRawData)
          u64ToHexString (uint64 s.PointerToRawData)
          u64ToHexString (uint64 s.PointerToRelocations)
          u64ToHexString (uint64 s.PointerToLineNumbers)
          s.NumberOfRelocations.ToString ()
          s.NumberOfLineNumbers.ToString ()
          u64ToHexString characteristics ])
      translateSectionChracteristics characteristics
      |> List.iter (fun str ->
        Printer.printrow (true, cfg, [ ""; ""; ""; ""; ""; ""; ""
                                       ""; ""; ""; ""; ""; str ])))
  else
    let cfg = [ LeftAligned 4; addrColumn; addrColumn; LeftAligned 24 ]
    Printer.printrow (true, cfg, [ "Num"; "Start"; "End"; "Name" ])
    Printer.println "  ---"
    fi.GetSections ()
    |> Seq.iteri (fun idx s ->
      Printer.printrow (true, cfg,
        [ wrapSqrdBrac (idx.ToString ())
          (addrToString fi.WordSize s.Address)
          (addrToString fi.WordSize (s.Address + s.Size - uint64 1))
          normalizeEmpty s.Name ]))

let dumpSectionDetails (secname: string) (fi: PEFileInfo) =
  let idx =
    Array.tryFindIndex (fun (s: SectionHeader) ->
      s.Name = secname) fi.PE.SectionHeaders
  match idx with
  | Some idx ->
    let section = fi.PE.SectionHeaders.[idx]
    let characteristics = uint64 section.SectionCharacteristics
    Printer.printTwoCols
      "Section number:"
      (wrapSqrdBrac (idx.ToString ()))
    Printer.printTwoCols
      "Section name:"
      section.Name
    Printer.printTwoCols
      "Virtual size:"
      (u64ToHexString (uint64 section.VirtualSize))
    Printer.printTwoCols
      "Virtual address:"
      (u64ToHexString (uint64 section.VirtualAddress))
    Printer.printTwoCols
      "Size of raw data:"
      (u64ToHexString (uint64 section.SizeOfRawData))
    Printer.printTwoCols
      "Pointer to raw data:"
      (u64ToHexString (uint64 section.PointerToRawData))
    Printer.printTwoCols
      "Pointer to relocations:"
      (u64ToHexString (uint64 section.PointerToRelocations))
    Printer.printTwoCols
      "Pointer to line numbers:"
      (u64ToHexString (uint64 section.PointerToLineNumbers))
    Printer.printTwoCols
      "Number of relocations:"
      (section.NumberOfRelocations.ToString ())
    Printer.printTwoCols
      "Number of line numbers:"
      (section.NumberOfLineNumbers.ToString ())
    Printer.printTwoCols
      "Characteristics:"
      (u64ToHexString characteristics)
    translateSectionChracteristics characteristics
    |> List.iter (fun str -> Printer.printTwoCols "" str)
  | None -> Printer.printTwoCols "" "Not found."

let printSymbolInfo (fi: PEFileInfo) (symbols: seq<Symbol>) =
  let addrColumn = columnWidthOfAddr fi |> LeftAligned
  let cfg = [ LeftAligned 5; addrColumn; LeftAligned 50; LeftAligned 15 ]
  Printer.printrow (true, cfg, [ "Kind"; "Address"; "Name"; "LibraryName" ])
  Printer.println "  ---"
  symbols
  |> Seq.sortBy (fun s -> s.Name)
  |> Seq.sortBy (fun s -> s.Address)
  |> Seq.sortBy (fun s -> s.Target)
  |> Seq.iter (fun s ->
    Printer.printrow (true, cfg,
      [ targetString s
        addrToString fi.WordSize s.Address
        normalizeEmpty s.Name
        (toLibString >> normalizeEmpty) s.LibraryName ]))

let dumpSymbols _ (fi: PEFileInfo) =
   fi.GetSymbols ()
   |> printSymbolInfo fi

let dumpRelocs _ (fi: PEFileInfo) =
  fi.GetRelocationSymbols ()
  |> printSymbolInfo fi

let dumpFunctions _ (fi: PEFileInfo) =
  fi.GetFunctionSymbols ()
  |> printSymbolInfo fi

let inline addrFromRVA baseAddr rva =
  uint64 rva + baseAddr

let dumpImports _ (fi: PEFileInfo) =
  let cfg = [ LeftAligned 50; LeftAligned 50; LeftAligned 20 ]
  Printer.printrow (true, cfg,
    [ "FunctionName"; "LibraryName"; "TableAddress" ])
  Printer.println "  ---"
  fi.PE.ImportMap
  |> Map.iter (fun addr info ->
    match info with
    | PE.ImportInfo.ImportByOrdinal (ordinal, dllname) ->
      Printer.printrow (true, cfg,
        [ "#" + ordinal.ToString ()
          dllname
          u64ToHexString (addrFromRVA fi.PE.BaseAddr addr) ])
    | PE.ImportInfo.ImportByName (_, fname, dllname) ->
      Printer.printrow (true, cfg,
        [ fname
          dllname
          u64ToHexString (addrFromRVA fi.PE.BaseAddr addr) ]))

let dumpExports _ (fi: PEFileInfo) =
  let cfg = [ LeftAligned 45; LeftAligned 20 ]
  Printer.printrow (true, cfg, [ "FunctionName"; "TableAddress" ])
  Printer.println "  ---"
  fi.PE.ExportMap
  |> Map.iter (fun addr names ->
    let rva = int (addr - fi.PE.BaseAddr)
    match fi.PE.FindSectionIdxFromRVA rva with
    | -1 -> ()
    | idx ->
      names
      |> List.iter (fun name ->
        Printer.printrow (true, cfg, [ name; u64ToHexString addr ])))
  Printer.println ""
  Printer.printrow (true, cfg, [ "FunctionName"; "ForwardName" ])
  Printer.println "  ---"
  fi.PE.ForwardMap
  |> Map.iter (fun name (bin, func) ->
    Printer.printrow (true, cfg, [ name; bin + "!" + func ]))

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

let dumpOptionalHeader _ (fi: PEFileInfo) =
  let hdr = fi.PE.PEHeaders.PEHeader
  let imageBase = hdr.ImageBase
  let sizeOfImage = uint64 hdr.SizeOfImage
  let entryPoint = u64ToHexString (imageBase + uint64 hdr.AddressOfEntryPoint)
  let startImage = u64ToHexString imageBase
  let endImage = u64ToHexString (imageBase + sizeOfImage - uint64 1)
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
  Printer.printTwoCols
    "Magic:"
    (u64ToHexString (uint64 hdr.Magic) + wrapParen (hdr.Magic.ToString ()))
  Printer.printTwoCols
    "Linker version:"
    (hdr.MajorLinkerVersion.ToString ()
    + "." + hdr.MinorLinkerVersion.ToString ())
  Printer.printTwoCols
    "Size of code:"
    (u64ToHexString (uint64 hdr.SizeOfCode))
  Printer.printTwoCols
    "Size of initialized data:"
    (u64ToHexString (uint64 hdr.SizeOfInitializedData))
  Printer.printTwoCols
    "Size of uninitialized data:"
    (u64ToHexString (uint64 hdr.SizeOfUninitializedData))
  Printer.printTwoCols
    "Entry point:"
    entryPoint
  Printer.printTwoCols
    "Base of code:"
    (u64ToHexString (uint64 hdr.BaseOfCode))
  Printer.printTwoCols
    "Image base:"
    (u64ToHexString imageBase + wrapParen (startImage + " to " + endImage))
  Printer.printTwoCols
    "Section alignment:"
    (u64ToHexString (uint64 hdr.SectionAlignment))
  Printer.printTwoCols
    "File Alignment:"
    (u64ToHexString (uint64 hdr.FileAlignment))
  Printer.printTwoCols
    "Operating system version:"
    (hdr.MajorOperatingSystemVersion.ToString ()
     + "." + hdr.MinorOperatingSystemVersion.ToString ())
  Printer.printTwoCols
    "Image version:"
    (hdr.MajorImageVersion.ToString ()
     + "." + hdr.MinorImageVersion.ToString ())
  Printer.printTwoCols
    "Subsystem version:"
    (hdr.MajorSubsystemVersion.ToString ()
     + "." + hdr.MinorSubsystemVersion.ToString ())
  Printer.printTwoCols
    "Size of image:"
    (u64ToHexString sizeOfImage)
  Printer.printTwoCols
    "Size of headers:"
    (u64ToHexString (uint64 hdr.SizeOfHeaders))
  Printer.printTwoCols
    "Checksum:"
    (u64ToHexString (uint64 hdr.CheckSum))
  Printer.printTwoCols
    "Subsystem:"
    (u64ToHexString (uint64 hdr.Subsystem)
      + wrapParen (hdr.Subsystem.ToString ()))
  Printer.printTwoCols
    "DLL characteristics:"
    (u64ToHexString (uint64 hdr.DllCharacteristics))
  translateDllChracteristcs (uint64 hdr.DllCharacteristics)
  |> List.iter (fun str -> Printer.printTwoCols "" str)
  Printer.printTwoCols
    "Size of stack reserve:"
    (u64ToHexString (uint64 hdr.SizeOfStackReserve))
  Printer.printTwoCols
    "Size of stack commit:"
    (u64ToHexString (uint64 hdr.SizeOfStackCommit))
  Printer.printTwoCols
    "Size of heap reserve:"
    (u64ToHexString (uint64 hdr.SizeOfHeapReserve))
  Printer.printTwoCols
    "Size of heap commit:"
    (u64ToHexString (uint64 hdr.SizeOfHeapCommit))
  Printer.printTwoCols
    "Loader flags (reserved):"
    "0x0"
  Printer.printTwoCols
    "Number of directories:"
    (hdr.NumberOfRvaAndSizes.ToString ())
  Printer.printTwoCols
    "RVA[size] of Export Table Directory:"
    (u64ToHexString (uint64 exportDir.RelativeVirtualAddress)
    + wrapSqrdBrac (u64ToHexString (uint64 exportDir.Size)))
  Printer.printTwoCols
    "RVA[size] of Import Table Directory:"
    (u64ToHexString (uint64 importDir.RelativeVirtualAddress)
    + wrapSqrdBrac (u64ToHexString (uint64 importDir.Size)))
  Printer.printTwoCols
    "RVA[size] of Resource Table Directory:"
    (u64ToHexString (uint64 resourceDir.RelativeVirtualAddress)
    + wrapSqrdBrac (u64ToHexString (uint64 resourceDir.Size)))
  Printer.printTwoCols
    "RVA[size] of Exception Table Directory:"
    (u64ToHexString (uint64 exceptionDir.RelativeVirtualAddress)
    + wrapSqrdBrac (u64ToHexString (uint64 exceptionDir.Size)))
  Printer.printTwoCols
    "RVA[size] of Certificate Table Directory:"
    (u64ToHexString (uint64 certificateDir.RelativeVirtualAddress)
    + wrapSqrdBrac (u64ToHexString (uint64 certificateDir.Size)))
  Printer.printTwoCols
    "RVA[size] of Base Relocation Table Directory:"
    (u64ToHexString (uint64 baseRelocDir.RelativeVirtualAddress)
    + wrapSqrdBrac (u64ToHexString (uint64 baseRelocDir.Size)))
  Printer.printTwoCols
    "RVA[size] of Debug Table Directory:"
    (u64ToHexString (uint64 debugDir.RelativeVirtualAddress)
    + wrapSqrdBrac (u64ToHexString (uint64 debugDir.Size)))
  Printer.printTwoCols
    "RVA[size] of Architecture Table Directory:"
    (u64ToHexString (uint64 architectureDir.RelativeVirtualAddress)
    + wrapSqrdBrac (u64ToHexString (uint64 architectureDir.Size)))
  Printer.printTwoCols
    "RVA[size] of Global Pointer Table Directory:"
    (u64ToHexString (uint64 globalPtrDir.RelativeVirtualAddress)
    + wrapSqrdBrac (u64ToHexString (uint64 globalPtrDir.Size)))
  Printer.printTwoCols
    "RVA[size] of Thread Storage Table Directory:"
    (u64ToHexString (uint64 threadLoStorDir.RelativeVirtualAddress)
    + wrapSqrdBrac (u64ToHexString (uint64 threadLoStorDir.Size)))
  Printer.printTwoCols
    "RVA[size] of Load Configuration Table Directory:"
    (u64ToHexString (uint64 loadConfigDir.RelativeVirtualAddress)
    + wrapSqrdBrac (u64ToHexString (uint64 loadConfigDir.Size)))
  Printer.printTwoCols
    "RVA[size] of Bound Import Table Directory:"
    (u64ToHexString (uint64 boundImpDir.RelativeVirtualAddress)
    + wrapSqrdBrac (u64ToHexString (uint64 boundImpDir.Size)))
  Printer.printTwoCols
    "RVA[size] of Import Address Table Directory:"
    (u64ToHexString (uint64 importAddrDir.RelativeVirtualAddress)
    + wrapSqrdBrac (u64ToHexString (uint64 importAddrDir.Size)))
  Printer.printTwoCols
    "RVA[size] of Delay Import Table Directory:"
    (u64ToHexString (uint64 delayImpDir.RelativeVirtualAddress)
    + wrapSqrdBrac (u64ToHexString (uint64 delayImpDir.Size)))
  Printer.printTwoCols
    "RVA[size] of COM Descriptor Table Directory:"
    (u64ToHexString (uint64 comDescDir.RelativeVirtualAddress)
    + wrapSqrdBrac (u64ToHexString (uint64 comDescDir.Size)))
  Printer.printTwoCols
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

let dumpCLRHeader _ (fi: PEFileInfo) =
  let hdr = fi.PE.PEHeaders.CorHeader
  if isNull hdr then
    Printer.printTwoCols "" "Not found."
  else
    let metaDataDir = hdr.MetadataDirectory
    let resourcesDir = hdr.ResourcesDirectory
    let strongNameSigDir = hdr.StrongNameSignatureDirectory
    let codeMgrTblDir = hdr.CodeManagerTableDirectory
    let vTableFixups = hdr.VtableFixupsDirectory
    let exportAddrTblJmps = hdr.ExportAddressTableJumpsDirectory
    let managedNativeHdr = hdr.ManagedNativeHeaderDirectory
    Printer.printTwoCols
      "Runtime version:"
      (hdr.MajorRuntimeVersion.ToString ()
      + "." + hdr.MinorRuntimeVersion.ToString ())
    Printer.printTwoCols
      "RVA[size] of Meta Data Directory:"
      (u64ToHexString (uint64 metaDataDir.RelativeVirtualAddress)
      + wrapSqrdBrac (u64ToHexString (uint64 metaDataDir.Size)))
    Printer.printTwoCols
      "Flags:"
      (u64ToHexString (uint64 hdr.Flags))
    translateCorFlags (uint64 hdr.Flags)
    |> List.iter (fun str -> Printer.printTwoCols "" str)
    Printer.printTwoCols
      "RVA[size] of Resources Directory:"
      (u64ToHexString (uint64 resourcesDir.RelativeVirtualAddress)
      + wrapSqrdBrac (u64ToHexString (uint64 resourcesDir.Size)))
    Printer.printTwoCols
      "RVA[size] of Strong Name Signature Directory:"
      (u64ToHexString (uint64 strongNameSigDir.RelativeVirtualAddress)
      + wrapSqrdBrac (u64ToHexString (uint64 strongNameSigDir.Size)))
    Printer.printTwoCols
      "RVA[size] of Code Manager Table Directory:"
      (u64ToHexString (uint64 codeMgrTblDir.RelativeVirtualAddress)
      + wrapSqrdBrac (u64ToHexString (uint64 codeMgrTblDir.Size)))
    Printer.printTwoCols
      "RVA[size] of VTable Fixups Directory:"
      (u64ToHexString (uint64 vTableFixups.RelativeVirtualAddress)
      + wrapSqrdBrac (u64ToHexString (uint64 vTableFixups.Size)))
    Printer.printTwoCols
      "RVA[size] of Export Address Table Jumps Directory:"
      (u64ToHexString (uint64 exportAddrTblJmps.RelativeVirtualAddress)
      + wrapSqrdBrac (u64ToHexString (uint64 exportAddrTblJmps.Size)))
    Printer.printTwoCols
      "RVA[size] of Managed Native Header Directory:"
      (u64ToHexString (uint64 managedNativeHdr.RelativeVirtualAddress)
      + wrapSqrdBrac (u64ToHexString (uint64 managedNativeHdr.Size)))

let dumpDependencies _ (fi: PEFileInfo) =
  fi.GetLinkageTableEntries ()
  |> Seq.map (fun e -> e.LibraryName)
  |> Set.ofSeq
  |> Set.iter (fun s -> Printer.printTwoCols s "")
