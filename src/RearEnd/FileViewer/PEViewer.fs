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
  out.PrintTwoCols
    "Machine:"
    (u64ToHexString (uint64 hdr.Machine) + wrapParen (hdr.Machine.ToString ()))
  out.PrintTwoCols
    "Number of sections:"
    (hdr.NumberOfSections.ToString ())
  out.PrintTwoCols
    "Time date stamp:"
    (hdr.TimeDateStamp.ToString ())
  out.PrintTwoCols
    "Pointer to symbol table:"
    (u64ToHexString (uint64 hdr.PointerToSymbolTable))
  out.PrintTwoCols
    "Size of optional header:"
    (u64ToHexString (uint64 hdr.SizeOfOptionalHeader))
  out.PrintTwoCols
    "Characteristics:"
    (u64ToHexString (uint64 hdr.Characteristics))
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
    out.PrintRow (true, cfg,
      [ "Num"; "Start"; "End"; "Name"
        "VirtSize"; "VirtAddr"; "RawSize"; "RawPtr"
        "RelocPtr"; "LineNPtr"; "RelocNum"; "LineNNum"
        "Characteristics" ])
    out.PrintLine "  ---"
    fi.PE.SectionHeaders
    |> Array.iteri (fun idx s ->
      let startAddr = fi.PE.BaseAddr + uint64 s.VirtualAddress
      let size =
        uint64 (if s.VirtualSize = 0 then s.SizeOfRawData else s.VirtualSize)
      let characteristics = uint64 s.SectionCharacteristics
      out.PrintRow (true, cfg,
        [ wrapSqrdBracket (idx.ToString ())
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
        out.PrintRow (true, cfg, [ ""; ""; ""; ""; ""; ""; ""
                                   ""; ""; ""; ""; ""; str ])))
  else
    let cfg = [ LeftAligned 4; addrColumn; addrColumn; LeftAligned 24 ]
    out.PrintRow (true, cfg, [ "Num"; "Start"; "End"; "Name" ])
    out.PrintLine "  ---"
    fi.GetSections ()
    |> Seq.iteri (fun idx s ->
      out.PrintRow (true, cfg,
        [ wrapSqrdBracket (idx.ToString ())
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
    out.PrintTwoCols
      "Section number:"
      (wrapSqrdBracket (idx.ToString ()))
    out.PrintTwoCols
      "Section name:"
      section.Name
    out.PrintTwoCols
      "Virtual size:"
      (u64ToHexString (uint64 section.VirtualSize))
    out.PrintTwoCols
      "Virtual address:"
      (u64ToHexString (uint64 section.VirtualAddress))
    out.PrintTwoCols
      "Size of raw data:"
      (u64ToHexString (uint64 section.SizeOfRawData))
    out.PrintTwoCols
      "Pointer to raw data:"
      (u64ToHexString (uint64 section.PointerToRawData))
    out.PrintTwoCols
      "Pointer to relocations:"
      (u64ToHexString (uint64 section.PointerToRelocations))
    out.PrintTwoCols
      "Pointer to line numbers:"
      (u64ToHexString (uint64 section.PointerToLineNumbers))
    out.PrintTwoCols
      "Number of relocations:"
      (section.NumberOfRelocations.ToString ())
    out.PrintTwoCols
      "Number of line numbers:"
      (section.NumberOfLineNumbers.ToString ())
    out.PrintTwoCols
      "Characteristics:"
      (u64ToHexString characteristics)
    translateSectionChracteristics characteristics
    |> List.iter (fun str -> out.PrintTwoCols "" str)
  | None -> out.PrintTwoCols "" "Not found."

let printSymbolInfo (fi: PEFileInfo) (symbols: seq<Symbol>) =
  let addrColumn = columnWidthOfAddr fi |> LeftAligned
  let cfg = [ LeftAligned 5; addrColumn; LeftAligned 50; LeftAligned 15 ]
  out.PrintRow (true, cfg, [ "Kind"; "Address"; "Name"; "LibraryName" ])
  out.PrintLine "  ---"
  symbols
  |> Seq.sortBy (fun s -> s.Name)
  |> Seq.sortBy (fun s -> s.Address)
  |> Seq.sortBy (fun s -> s.Target)
  |> Seq.iter (fun s ->
    out.PrintRow (true, cfg,
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
  out.PrintRow (true, cfg,
    [ "FunctionName"; "LibraryName"; "TableAddress" ])
  out.PrintLine "  ---"
  fi.PE.ImportMap
  |> Map.iter (fun addr info ->
    match info with
    | PE.ImportInfo.ImportByOrdinal (ordinal, dllname) ->
      out.PrintRow (true, cfg,
        [ "#" + ordinal.ToString ()
          dllname
          u64ToHexString (addrFromRVA fi.PE.BaseAddr addr) ])
    | PE.ImportInfo.ImportByName (_, fname, dllname) ->
      out.PrintRow (true, cfg,
        [ fname
          dllname
          u64ToHexString (addrFromRVA fi.PE.BaseAddr addr) ]))

let dumpExports _ (fi: PEFileInfo) =
  let cfg = [ LeftAligned 45; LeftAligned 20 ]
  out.PrintRow (true, cfg, [ "FunctionName"; "TableAddress" ])
  out.PrintLine "  ---"
  fi.PE.ExportMap
  |> Map.iter (fun addr names ->
    let rva = int (addr - fi.PE.BaseAddr)
    match fi.PE.FindSectionIdxFromRVA rva with
    | -1 -> ()
    | idx ->
      names
      |> List.iter (fun name ->
        out.PrintRow (true, cfg, [ name; u64ToHexString addr ])))
  out.PrintLine ""
  out.PrintRow (true, cfg, [ "FunctionName"; "ForwardName" ])
  out.PrintLine "  ---"
  fi.PE.ForwardMap
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
  out.PrintTwoCols
    "Magic:"
    (u64ToHexString (uint64 hdr.Magic) + wrapParen (hdr.Magic.ToString ()))
  out.PrintTwoCols
    "Linker version:"
    (hdr.MajorLinkerVersion.ToString ()
    + "." + hdr.MinorLinkerVersion.ToString ())
  out.PrintTwoCols
    "Size of code:"
    (u64ToHexString (uint64 hdr.SizeOfCode))
  out.PrintTwoCols
    "Size of initialized data:"
    (u64ToHexString (uint64 hdr.SizeOfInitializedData))
  out.PrintTwoCols
    "Size of uninitialized data:"
    (u64ToHexString (uint64 hdr.SizeOfUninitializedData))
  out.PrintTwoCols
    "Entry point:"
    entryPoint
  out.PrintTwoCols
    "Base of code:"
    (u64ToHexString (uint64 hdr.BaseOfCode))
  out.PrintTwoCols
    "Image base:"
    (u64ToHexString imageBase + wrapParen (startImage + " to " + endImage))
  out.PrintTwoCols
    "Section alignment:"
    (u64ToHexString (uint64 hdr.SectionAlignment))
  out.PrintTwoCols
    "File Alignment:"
    (u64ToHexString (uint64 hdr.FileAlignment))
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
    (u64ToHexString sizeOfImage)
  out.PrintTwoCols
    "Size of headers:"
    (u64ToHexString (uint64 hdr.SizeOfHeaders))
  out.PrintTwoCols
    "Checksum:"
    (u64ToHexString (uint64 hdr.CheckSum))
  out.PrintTwoCols
    "Subsystem:"
    (u64ToHexString (uint64 hdr.Subsystem)
      + wrapParen (hdr.Subsystem.ToString ()))
  out.PrintTwoCols
    "DLL characteristics:"
    (u64ToHexString (uint64 hdr.DllCharacteristics))
  translateDllChracteristcs (uint64 hdr.DllCharacteristics)
  |> List.iter (fun str -> out.PrintTwoCols "" str)
  out.PrintTwoCols
    "Size of stack reserve:"
    (u64ToHexString (uint64 hdr.SizeOfStackReserve))
  out.PrintTwoCols
    "Size of stack commit:"
    (u64ToHexString (uint64 hdr.SizeOfStackCommit))
  out.PrintTwoCols
    "Size of heap reserve:"
    (u64ToHexString (uint64 hdr.SizeOfHeapReserve))
  out.PrintTwoCols
    "Size of heap commit:"
    (u64ToHexString (uint64 hdr.SizeOfHeapCommit))
  out.PrintTwoCols
    "Loader flags (reserved):"
    "0x0"
  out.PrintTwoCols
    "Number of directories:"
    (hdr.NumberOfRvaAndSizes.ToString ())
  out.PrintTwoCols
    "RVA[size] of Export Table Directory:"
    (u64ToHexString (uint64 exportDir.RelativeVirtualAddress)
    + wrapSqrdBracket (u64ToHexString (uint64 exportDir.Size)))
  out.PrintTwoCols
    "RVA[size] of Import Table Directory:"
    (u64ToHexString (uint64 importDir.RelativeVirtualAddress)
    + wrapSqrdBracket (u64ToHexString (uint64 importDir.Size)))
  out.PrintTwoCols
    "RVA[size] of Resource Table Directory:"
    (u64ToHexString (uint64 resourceDir.RelativeVirtualAddress)
    + wrapSqrdBracket (u64ToHexString (uint64 resourceDir.Size)))
  out.PrintTwoCols
    "RVA[size] of Exception Table Directory:"
    (u64ToHexString (uint64 exceptionDir.RelativeVirtualAddress)
    + wrapSqrdBracket (u64ToHexString (uint64 exceptionDir.Size)))
  out.PrintTwoCols
    "RVA[size] of Certificate Table Directory:"
    (u64ToHexString (uint64 certificateDir.RelativeVirtualAddress)
    + wrapSqrdBracket (u64ToHexString (uint64 certificateDir.Size)))
  out.PrintTwoCols
    "RVA[size] of Base Relocation Table Directory:"
    (u64ToHexString (uint64 baseRelocDir.RelativeVirtualAddress)
    + wrapSqrdBracket (u64ToHexString (uint64 baseRelocDir.Size)))
  out.PrintTwoCols
    "RVA[size] of Debug Table Directory:"
    (u64ToHexString (uint64 debugDir.RelativeVirtualAddress)
    + wrapSqrdBracket (u64ToHexString (uint64 debugDir.Size)))
  out.PrintTwoCols
    "RVA[size] of Architecture Table Directory:"
    (u64ToHexString (uint64 architectureDir.RelativeVirtualAddress)
    + wrapSqrdBracket (u64ToHexString (uint64 architectureDir.Size)))
  out.PrintTwoCols
    "RVA[size] of Global Pointer Table Directory:"
    (u64ToHexString (uint64 globalPtrDir.RelativeVirtualAddress)
    + wrapSqrdBracket (u64ToHexString (uint64 globalPtrDir.Size)))
  out.PrintTwoCols
    "RVA[size] of Thread Storage Table Directory:"
    (u64ToHexString (uint64 threadLoStorDir.RelativeVirtualAddress)
    + wrapSqrdBracket (u64ToHexString (uint64 threadLoStorDir.Size)))
  out.PrintTwoCols
    "RVA[size] of Load Configuration Table Directory:"
    (u64ToHexString (uint64 loadConfigDir.RelativeVirtualAddress)
    + wrapSqrdBracket (u64ToHexString (uint64 loadConfigDir.Size)))
  out.PrintTwoCols
    "RVA[size] of Bound Import Table Directory:"
    (u64ToHexString (uint64 boundImpDir.RelativeVirtualAddress)
    + wrapSqrdBracket (u64ToHexString (uint64 boundImpDir.Size)))
  out.PrintTwoCols
    "RVA[size] of Import Address Table Directory:"
    (u64ToHexString (uint64 importAddrDir.RelativeVirtualAddress)
    + wrapSqrdBracket (u64ToHexString (uint64 importAddrDir.Size)))
  out.PrintTwoCols
    "RVA[size] of Delay Import Table Directory:"
    (u64ToHexString (uint64 delayImpDir.RelativeVirtualAddress)
    + wrapSqrdBracket (u64ToHexString (uint64 delayImpDir.Size)))
  out.PrintTwoCols
    "RVA[size] of COM Descriptor Table Directory:"
    (u64ToHexString (uint64 comDescDir.RelativeVirtualAddress)
    + wrapSqrdBracket (u64ToHexString (uint64 comDescDir.Size)))
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

let dumpCLRHeader _ (fi: PEFileInfo) =
  let hdr = fi.PE.PEHeaders.CorHeader
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
      (u64ToHexString (uint64 metaDataDir.RelativeVirtualAddress)
      + wrapSqrdBracket (u64ToHexString (uint64 metaDataDir.Size)))
    out.PrintTwoCols
      "Flags:"
      (u64ToHexString (uint64 hdr.Flags))
    translateCorFlags (uint64 hdr.Flags)
    |> List.iter (fun str -> out.PrintTwoCols "" str)
    out.PrintTwoCols
      "RVA[size] of Resources Directory:"
      (u64ToHexString (uint64 resourcesDir.RelativeVirtualAddress)
      + wrapSqrdBracket (u64ToHexString (uint64 resourcesDir.Size)))
    out.PrintTwoCols
      "RVA[size] of Strong Name Signature Directory:"
      (u64ToHexString (uint64 strongNameSigDir.RelativeVirtualAddress)
      + wrapSqrdBracket (u64ToHexString (uint64 strongNameSigDir.Size)))
    out.PrintTwoCols
      "RVA[size] of Code Manager Table Directory:"
      (u64ToHexString (uint64 codeMgrTblDir.RelativeVirtualAddress)
      + wrapSqrdBracket (u64ToHexString (uint64 codeMgrTblDir.Size)))
    out.PrintTwoCols
      "RVA[size] of VTable Fixups Directory:"
      (u64ToHexString (uint64 vTableFixups.RelativeVirtualAddress)
      + wrapSqrdBracket (u64ToHexString (uint64 vTableFixups.Size)))
    out.PrintTwoCols
      "RVA[size] of Export Address Table Jumps Directory:"
      (u64ToHexString (uint64 exportAddrTblJmps.RelativeVirtualAddress)
      + wrapSqrdBracket (u64ToHexString (uint64 exportAddrTblJmps.Size)))
    out.PrintTwoCols
      "RVA[size] of Managed Native Header Directory:"
      (u64ToHexString (uint64 managedNativeHdr.RelativeVirtualAddress)
      + wrapSqrdBracket (u64ToHexString (uint64 managedNativeHdr.Size)))

let dumpDependencies _ (fi: PEFileInfo) =
  fi.GetLinkageTableEntries ()
  |> Seq.map (fun e -> e.LibraryName)
  |> Set.ofSeq
  |> Set.iter (fun s -> out.PrintTwoCols s "")
