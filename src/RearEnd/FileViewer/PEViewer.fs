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
open B2R2.RearEnd.FileViewer.Helper
open System.Reflection.PortableExecutable

let badAccess _ _ =
  raise InvalidFileTypeException

let translateChracteristics c =
  let ec =
    System.Enum.GetValues (typeof<Characteristics>)
    :?> Characteristics []
    |> Array.toList
  let rec loop acc c = function
    | [] -> List.rev acc
    | ec :: t ->
      if uint64 ec &&& c = uint64 ec then
        loop ((" - " + ec.ToString ()) :: acc) c t
      else
        loop acc c t
  loop [] c ec

let dumpFileHeader _ (fi: PEFileInfo) =
  let hdr = fi.PE.PEHeaders.CoffHeader
  printTwoCols
    "Machine:"
    (toHexString (uint64 hdr.Machine) + wrapParen (hdr.Machine.ToString ()))
  printTwoCols
    "Number of sections:"
    (hdr.NumberOfSections.ToString ())
  printTwoCols
    "Time date stamp:"
    (hdr.TimeDateStamp.ToString ())
  printTwoCols
    "Pointer to symbol table:"
    (toHexString (uint64 hdr.PointerToSymbolTable))
  printTwoCols
    "Size of optional header:"
    (toHexString (uint64 hdr.SizeOfOptionalHeader))
  printTwoCols
    "Characteristics:"
    (toHexString (uint64 hdr.Characteristics))
  translateChracteristics (uint64 hdr.Characteristics)
  |> List.iter (fun s -> printTwoCols "" s)

let translateSectionChracteristics c =
  let ec =
    System.Enum.GetValues (typeof<SectionCharacteristics>)
    :?> SectionCharacteristics []
    |> Array.toList
  if c = uint64 0 then
    [ " - TypeReg" ]
  else
    let rec loop acc c = function
      | [] -> List.rev acc
      | ec :: t ->
        if uint64 ec &&& c = uint64 ec && not (uint64 ec = uint64 0) then
          loop ((" - " + ec.ToString ()) :: acc) c t
        else
          loop acc c t
    loop [] c ec

let dumpSectionHeaders (opts: FileViewerOpts) (fi: PEFileInfo) =
  if opts.Verbose then
    let cfg = [ LeftAligned 28; LeftAligned 20; LeftAligned 20; LeftAligned 24 ]
    Printer.printrow true cfg [ "Num"; "Start"; "End"; "Name" ]
    Printer.printrow true cfg [ "VirtSize"; "VirtAddr"; "RawSize"; "RawPtr" ]
    Printer.printrow true cfg [ "RelocPtr"; "LineNPtr"; "RelocNum"; "LineNNum" ]
    Printer.printrow true cfg [ "Characteristics"; ""; ""; "" ]
    Printer.println "  ---"
    fi.PE.SectionHeaders
    |> Array.iteri (fun idx s ->
      let startAddr = fi.PE.BaseAddr + uint64 s.VirtualAddress
      let size =
        uint64 (if s.VirtualSize = 0 then s.SizeOfRawData else s.VirtualSize)
      let characteristics = uint64 s.SectionCharacteristics
      Printer.printrow true cfg
        [ wrapSqrdBrac (idx.ToString ())
          (addrToString fi.WordSize startAddr)
          (addrToString fi.WordSize (startAddr + size - uint64 1))
          normalizeEmpty s.Name ]
      Printer.printrow true cfg
        [ toHexString (uint64 s.VirtualSize)
          toHexString (uint64 s.VirtualAddress)
          toHexString (uint64 s.SizeOfRawData)
          toHexString (uint64 s.PointerToRawData) ]
      Printer.printrow true cfg
        [ toHexString (uint64 s.PointerToRelocations)
          toHexString (uint64 s.PointerToLineNumbers)
          s.NumberOfRelocations.ToString ()
          s.NumberOfLineNumbers.ToString () ]
      Printer.printrow true cfg
        [ toHexString characteristics; ""; ""; "" ]
      translateSectionChracteristics characteristics
      |> List.iter (fun str -> Printer.printrow true cfg [ str; ""; ""; "" ]))
  else
    let addrColumn = columnWidthOfAddr fi |> LeftAligned
    let cfg = [ LeftAligned 4; addrColumn; addrColumn; LeftAligned 24 ]
    Printer.printrow true cfg [ "Num"; "Start"; "End"; "Name" ]
    Printer.println "  ---"
    fi.GetSections ()
    |> Seq.iteri (fun idx s ->
      Printer.printrow true cfg
        [ wrapSqrdBrac (idx.ToString ())
          (addrToString fi.WordSize s.Address)
          (addrToString fi.WordSize (s.Address + s.Size - uint64 1))
          normalizeEmpty s.Name ])

let dumpSectionDetails (secname: string) (fi: PEFileInfo) =
  let idx =
    Array.tryFindIndex (fun (s: SectionHeader) ->
      s.Name = secname) fi.PE.SectionHeaders
  match idx with
  | Some idx ->
    let section = fi.PE.SectionHeaders.[idx]
    let characteristics = uint64 section.SectionCharacteristics
    printTwoCols
      "Section number:"
      (wrapSqrdBrac (idx.ToString ()))
    printTwoCols
      "Section name:"
      section.Name
    printTwoCols
      "Virtual size:"
      (toHexString (uint64 section.VirtualSize))
    printTwoCols
      "Virtual address:"
      (toHexString (uint64 section.VirtualAddress))
    printTwoCols
      "Size of raw data:"
      (toHexString (uint64 section.SizeOfRawData))
    printTwoCols
      "Pointer to raw data:"
      (toHexString (uint64 section.PointerToRawData))
    printTwoCols
      "Pointer to relocations:"
      (toHexString (uint64 section.PointerToRelocations))
    printTwoCols
      "Pointer to line numbers:"
      (toHexString (uint64 section.PointerToLineNumbers))
    printTwoCols
      "Number of relocations:"
      (section.NumberOfRelocations.ToString ())
    printTwoCols
      "Number of line numbers:"
      (section.NumberOfLineNumbers.ToString ())
    printTwoCols
      "Characteristics:"
      (toHexString characteristics)
    translateSectionChracteristics characteristics
    |> List.iter (fun s -> printTwoCols "" s)
  | None -> printTwoCols "Not found." ""

let printSymbolInfo (fi: PEFileInfo) (symbols: seq<Symbol>) =
  let addrColumn = columnWidthOfAddr fi |> LeftAligned
  let cfg = [ LeftAligned 5; addrColumn; LeftAligned 50; LeftAligned 15 ]
  Printer.printrow true cfg [ "Kind"; "Address"; "Name"; "LibraryName" ]
  Printer.println "  ---"
  symbols
  |> Seq.sortBy (fun s -> s.Name)
  |> Seq.sortBy (fun s -> s.Address)
  |> Seq.sortBy (fun s -> s.Target)
  |> Seq.iter (fun s ->
    Printer.printrow true cfg
      [ targetString s
        addrToString fi.WordSize s.Address
        normalizeEmpty s.Name
        (normalizeEmpty >> toLibString) s.LibraryName ])

let dumpSymbols _ (fi: PEFileInfo) =
   fi.GetSymbols ()
   |> printSymbolInfo fi

let dumpRelocs _ (fi: PEFileInfo) =
  fi.GetRelocationSymbols ()
  |> printSymbolInfo fi

let dumpFunctions _ (fi: PEFileInfo) =
  fi.GetFunctionSymbols ()
  |> printSymbolInfo fi

let dumpSegments _ _ = ()

let dumpLinkageTable _ _ = ()

let inline addrFromRVA baseAddr rva =
  uint64 rva + baseAddr

let dumpImports _ (fi: PEFileInfo) =
  let cfg = [ LeftAligned 50; LeftAligned 50; LeftAligned 20 ]
  Printer.printrow true cfg [ "FunctionName"; "LibraryName"; "TableAddress" ]
  Printer.println "  ---"
  fi.PE.ImportMap
  |> Map.iter (fun addr info ->
    match info with
    | PE.ImportInfo.ImportByOrdinal (ordinal, dllname) ->
      Printer.printrow true cfg
        [ "#" + ordinal.ToString ()
          dllname
          toHexString (addrFromRVA fi.PE.BaseAddr addr) ]
    | PE.ImportInfo.ImportByName (_, fname, dllname) ->
      Printer.printrow true cfg
        [ fname
          dllname
          toHexString (addrFromRVA fi.PE.BaseAddr addr) ])

let dumpExports _ (fi: PEFileInfo) =
  let cfg = [ LeftAligned 45; LeftAligned 20 ]
  Printer.printrow true cfg
    [ "FunctionName"; "TableAddress" ]
  Printer.println "  ---"
  fi.PE.ExportMap
  |> Map.iter (fun addr names ->
    let rva = int (addr - fi.PE.BaseAddr)
    match fi.PE.FindSectionIdxFromRVA rva with
    | -1 -> ()
    | idx ->
      names
      |> List.iter (fun name ->
        Printer.printrow true cfg [ name; toHexString addr ]))
  Printer.println ""
  Printer.printrow true cfg
    [ "FunctionName"; "ForwardName" ]
  Printer.println "  ---"
  fi.PE.ForwardMap
  |> Map.iter (fun name (bin, func) ->
    Printer.printrow true cfg [ name; bin + "!" + func ])

let translateDllChracteristcs c =
  let ec =
    System.Enum.GetValues (typeof<DllCharacteristics>)
    :?> DllCharacteristics []
    |> Array.toList
  let rec loop acc c = function
    | [] -> List.rev acc
    | ec :: t as a ->
      if uint64 ec &&& c = uint64 ec then
        loop ((" - " + ec.ToString ()) :: acc) c t
      elif uint64 0x0080 &&& c = uint64 0x0080 then
        loop (" - ForceIntegrity" :: acc) (c ^^^ uint64 0x0080) a
      elif uint64 0x4000 &&& c = uint64 0x4000 then
        loop (" - ControlFlowGuard" :: acc) (c ^^^ uint64 0x4000) a
      else
        loop acc c t
  loop [] c ec

let dumpOptionalHeader _ (fi: PEFileInfo) =
  let hdr = fi.PE.PEHeaders.PEHeader
  let imageBase = hdr.ImageBase
  let sizeOfImage = uint64 hdr.SizeOfImage
  let entryPoint = toHexString (imageBase + uint64 hdr.AddressOfEntryPoint)
  let startImage = toHexString imageBase
  let endImage = toHexString (imageBase + sizeOfImage - uint64 1)
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
  printTwoCols
    "Magic:"
    (toHexString (uint64 hdr.Magic) + wrapParen (hdr.Magic.ToString ()))
  printTwoCols
    "Linker version:"
    (hdr.MajorLinkerVersion.ToString ()
    + "." + hdr.MinorLinkerVersion.ToString ())
  printTwoCols
    "Size of code:"
    (toHexString (uint64 hdr.SizeOfCode))
  printTwoCols
    "Size of initialized data:"
    (toHexString (uint64 hdr.SizeOfInitializedData))
  printTwoCols
    "Size of uninitialized data:"
    (toHexString (uint64 hdr.SizeOfUninitializedData))
  printTwoCols
    "Entry point:"
    entryPoint
  printTwoCols
    "Base of code:"
    (toHexString (uint64 hdr.BaseOfCode))
  printTwoCols
    "Image base:"
    (toHexString imageBase + wrapParen (startImage + " to " + endImage))
  printTwoCols
    "Section alignment:"
    (toHexString (uint64 hdr.SectionAlignment))
  printTwoCols
    "File Alignment:"
    (toHexString (uint64 hdr.FileAlignment))
  printTwoCols
    "Operating system version:"
    (hdr.MajorOperatingSystemVersion.ToString ()
     + "." + hdr.MinorOperatingSystemVersion.ToString ())
  printTwoCols
    "Image version:"
    (hdr.MajorImageVersion.ToString ()
     + "." + hdr.MinorImageVersion.ToString ())
  printTwoCols
    "Subsystem version:"
    (hdr.MajorSubsystemVersion.ToString ()
     + "." + hdr.MinorSubsystemVersion.ToString ())
  printTwoCols
    "Size of image:"
    (toHexString sizeOfImage)
  printTwoCols
    "Size of headers:"
    (toHexString (uint64 hdr.SizeOfHeaders))
  printTwoCols
    "Checksum:"
    (toHexString (uint64 hdr.CheckSum))
  printTwoCols
    "Subsystem:"
    (toHexString (uint64 hdr.Subsystem) + wrapParen (hdr.Subsystem.ToString ()))
  printTwoCols
    "DLL characteristics:"
    (toHexString (uint64 hdr.DllCharacteristics))
  translateDllChracteristcs (uint64 hdr.DllCharacteristics)
  |> List.iter (fun s -> printTwoCols "" s)
  printTwoCols
    "Size of stack reserve:"
    (toHexString (uint64 hdr.SizeOfStackReserve))
  printTwoCols
    "Size of stack commit:"
    (toHexString (uint64 hdr.SizeOfStackCommit))
  printTwoCols
    "Size of heap reserve:"
    (toHexString (uint64 hdr.SizeOfHeapReserve))
  printTwoCols
    "Size of heap commit:"
    (toHexString (uint64 hdr.SizeOfHeapCommit))
  printTwoCols
    "Loader flags (reserved):"
    "0x0"
  printTwoCols
    "Number of directories:"
    (hdr.NumberOfRvaAndSizes.ToString ())
  printTwoCols
    "RVA[size] of Export Table Directory:"
    (toHexString (uint64 exportDir.RelativeVirtualAddress)
    + wrapSqrdBrac (toHexString (uint64 exportDir.Size)))
  printTwoCols
    "RVA[size] of Import Table Directory:"
    (toHexString (uint64 importDir.RelativeVirtualAddress)
    + wrapSqrdBrac (toHexString (uint64 importDir.Size)))
  printTwoCols
    "RVA[size] of Resource Table Directory:"
    (toHexString (uint64 resourceDir.RelativeVirtualAddress)
    + wrapSqrdBrac (toHexString (uint64 resourceDir.Size)))
  printTwoCols
    "RVA[size] of Exception Table Directory:"
    (toHexString (uint64 exceptionDir.RelativeVirtualAddress)
    + wrapSqrdBrac (toHexString (uint64 exceptionDir.Size)))
  printTwoCols
    "RVA[size] of Certificate Table Directory:"
    (toHexString (uint64 certificateDir.RelativeVirtualAddress)
    + wrapSqrdBrac (toHexString (uint64 certificateDir.Size)))
  printTwoCols
    "RVA[size] of Base Relocation Table Directory:"
    (toHexString (uint64 baseRelocDir.RelativeVirtualAddress)
    + wrapSqrdBrac (toHexString (uint64 baseRelocDir.Size)))
  printTwoCols
    "RVA[size] of Debug Table Directory:"
    (toHexString (uint64 debugDir.RelativeVirtualAddress)
    + wrapSqrdBrac (toHexString (uint64 debugDir.Size)))
  printTwoCols
    "RVA[size] of Architecture Table Directory:"
    (toHexString (uint64 architectureDir.RelativeVirtualAddress)
    + wrapSqrdBrac (toHexString (uint64 architectureDir.Size)))
  printTwoCols
    "RVA[size] of Global Pointer Table Directory:"
    (toHexString (uint64 globalPtrDir.RelativeVirtualAddress)
    + wrapSqrdBrac (toHexString (uint64 globalPtrDir.Size)))
  printTwoCols
    "RVA[size] of Thread Storage Table Directory:"
    (toHexString (uint64 threadLoStorDir.RelativeVirtualAddress)
    + wrapSqrdBrac (toHexString (uint64 threadLoStorDir.Size)))
  printTwoCols
    "RVA[size] of Load Configuration Table Directory:"
    (toHexString (uint64 loadConfigDir.RelativeVirtualAddress)
    + wrapSqrdBrac (toHexString (uint64 loadConfigDir.Size)))
  printTwoCols
    "RVA[size] of Bound Import Table Directory:"
    (toHexString (uint64 boundImpDir.RelativeVirtualAddress)
    + wrapSqrdBrac (toHexString (uint64 boundImpDir.Size)))
  printTwoCols
    "RVA[size] of Import Address Table Directory:"
    (toHexString (uint64 importAddrDir.RelativeVirtualAddress)
    + wrapSqrdBrac (toHexString (uint64 importAddrDir.Size)))
  printTwoCols
    "RVA[size] of Delay Import Table Directory:"
    (toHexString (uint64 delayImpDir.RelativeVirtualAddress)
    + wrapSqrdBrac (toHexString (uint64 delayImpDir.Size)))
  printTwoCols
    "RVA[size] of COM Descriptor Table Directory:"
    (toHexString (uint64 comDescDir.RelativeVirtualAddress)
    + wrapSqrdBrac (toHexString (uint64 comDescDir.Size)))
  printTwoCols
    "RVA[size] of Reserved Directory:"
    "0x0[0x0]"

let translateCorFlags f =
  let ef =
    System.Enum.GetValues (typeof<CorFlags>)
    :?> CorFlags []
    |> Array.toList
  let rec loop acc f = function
    | [] -> List.rev acc
    | ef :: t ->
      if uint64 ef &&& f = uint64 ef then
        loop ((" - " + ef.ToString ()) :: acc) f t
      else
        loop acc f t
  loop [] f ef

let dumpCLRHeader _ (fi: PEFileInfo) =
  let hdr = fi.PE.PEHeaders.CorHeader
  if isNull hdr then
    printTwoCols "Not found." ""
  else
    let metaDataDir = hdr.MetadataDirectory
    let resourcesDir = hdr.ResourcesDirectory
    let strongNameSigDir = hdr.StrongNameSignatureDirectory
    let codeMgrTblDir = hdr.CodeManagerTableDirectory
    let vTableFixups = hdr.VtableFixupsDirectory
    let exportAddrTblJmps = hdr.ExportAddressTableJumpsDirectory
    let managedNativeHdr = hdr.ManagedNativeHeaderDirectory
    printTwoCols
      "Runtime version:"
      (hdr.MajorRuntimeVersion.ToString ()
      + "." + hdr.MinorRuntimeVersion.ToString ())
    printTwoCols
      "RVA[size] of Meta Data Directory:"
      (toHexString (uint64 metaDataDir.RelativeVirtualAddress)
      + wrapSqrdBrac (toHexString (uint64 metaDataDir.Size)))
    printTwoCols
      "Flags:"
      (toHexString (uint64 hdr.Flags))
    translateCorFlags (uint64 hdr.Flags)
    |> List.iter (fun s -> printTwoCols "" s)
    printTwoCols
      "RVA[size] of Resources Directory:"
      (toHexString (uint64 resourcesDir.RelativeVirtualAddress)
      + wrapSqrdBrac (toHexString (uint64 resourcesDir.Size)))
    printTwoCols
      "RVA[size] of Strong Name Signature Directory:"
      (toHexString (uint64 strongNameSigDir.RelativeVirtualAddress)
      + wrapSqrdBrac (toHexString (uint64 strongNameSigDir.Size)))
    printTwoCols
      "RVA[size] of Code Manager Table Directory:"
      (toHexString (uint64 codeMgrTblDir.RelativeVirtualAddress)
      + wrapSqrdBrac (toHexString (uint64 codeMgrTblDir.Size)))
    printTwoCols
      "RVA[size] of VTable Fixups Directory:"
      (toHexString (uint64 vTableFixups.RelativeVirtualAddress)
      + wrapSqrdBrac (toHexString (uint64 vTableFixups.Size)))
    printTwoCols
      "RVA[size] of Export Address Table Jumps Directory:"
      (toHexString (uint64 exportAddrTblJmps.RelativeVirtualAddress)
      + wrapSqrdBrac (toHexString (uint64 exportAddrTblJmps.Size)))
    printTwoCols
      "RVA[size] of Managed Native Header Directory:"
      (toHexString (uint64 managedNativeHdr.RelativeVirtualAddress)
      + wrapSqrdBrac (toHexString (uint64 managedNativeHdr.Size)))

let dumpDependencies _ (fi: PEFileInfo) =
  fi.GetLinkageTableEntries ()
  |> Seq.map (fun e -> e.LibraryName)
  |> Set.ofSeq
  |> Set.iter (fun s -> printTwoCols s "")
