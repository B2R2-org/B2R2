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

module B2R2.RearEnd.FileViewer.ELFViewer

open B2R2
open B2R2.FrontEnd.BinInterface
open B2R2.FrontEnd.BinFile
open B2R2.RearEnd
open B2R2.RearEnd.Printer
open B2R2.RearEnd.FileViewer.Helper

let badAccess _ _ =
  raise InvalidFileTypeException

let computeMagicBytes (fi: ELFFileInfo) =
  fi.ELF.BinReader.PeekBytes (16, 0) |> ColoredSegment.colorBytes

let dumpFileHeader (_: FileViewerOpts) (fi: ELFFileInfo) =
  let hdr = fi.ELF.ELFHdr
  printTwoColsWithCS "Magic:" (computeMagicBytes fi)
  printTwoCols "Class:" ("ELF" + WordSize.toString hdr.Class)
  printTwoCols "Data:" (Endian.toString hdr.Endian + " endian")
  printTwoCols "Version:" (hdr.Version.ToString ())
  printTwoCols "ABI:" (hdr.OSABI.ToString ())
  printTwoCols "ABI version:" (hdr.OSABIVersion.ToString ())
  printTwoCols "Type:" (hdr.ELFFileType.ToString ())
  printTwoCols "Machine:" (hdr.MachineType.ToString ())
  printTwoColsHi "Entry point:" (toHexString hdr.EntryPoint)
  printTwoCols "PHdr table offset:" (toHexString hdr.PHdrTblOffset)
  printTwoCols "SHdr table offset:" (toHexString hdr.SHdrTblOffset)
  printTwoCols "Flags:" (toHexString (uint64 hdr.ELFFlags))
  printTwoCols "Header size:" (toNBytes (uint64 hdr.HeaderSize))
  printTwoCols "PHdr Entry Size:" (toNBytes (uint64 hdr.PHdrEntrySize))
  printTwoCols "PHdr Entry Num:" (hdr.PHdrNum.ToString ())
  printTwoCols "SHdr Entry Size:" (toNBytes (uint64 (hdr.SHdrEntrySize)))
  printTwoCols "SHdr Entry Num:" (hdr.SHdrNum.ToString ())
  printTwoCols "SHdr string index:" (hdr.SHdrStrIdx.ToString ())

let dumpSectionHeaders (opts: FileViewerOpts) (fi: ELFFileInfo) =
  let addrColumn = columnWidthOfAddr fi |> LeftAligned
  if opts.Verbose then
    let cfg = [ LeftAligned 4; addrColumn; addrColumn; LeftAligned 24;
                LeftAligned 14; LeftAligned 12; LeftAligned 8; LeftAligned 10;
                LeftAligned 4; LeftAligned 4; LeftAligned 6; LeftAligned 20 ]
    Printer.printrow true cfg [ "Num"; "Start"; "End"; "Name"
                                "Type"; "Offset"; "Size"; "EntrySize"
                                "Link"; "Info"; "Align"; "Flags" ]
    Printer.println "  ---"
    fi.ELF.SecInfo.SecByNum
    |> Array.iteri (fun idx s ->
      Printer.printrow true cfg
        [ wrapSqrdBrac (idx.ToString ())
          (addrToString fi.WordSize s.SecAddr)
          (addrToString fi.WordSize (s.SecAddr + s.SecSize - uint64 1))
          normalizeEmpty s.SecName
          s.SecType.ToString ()
          toHexString s.SecOffset
          toHexString s.SecSize
          toHexString s.SecEntrySize
          s.SecLink.ToString ()
          s.SecInfo.ToString ()
          toHexString s.SecAlignment
          s.SecFlags.ToString () ])
  else
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

let dumpSectionDetails (secname: string) (fi: ELFFileInfo) =
  match fi.ELF.SecInfo.SecByName.TryFind secname with
  | Some section ->
    printTwoCols "Section number:" (section.SecNum.ToString ())
    printTwoCols "Section name:" section.SecName
    printTwoCols "Type:" (section.SecType.ToString ())
    printTwoCols "Address:" (toHexString section.SecAddr)
    printTwoCols "Offset:" (toHexString section.SecOffset)
    printTwoCols "Size:" (toHexString section.SecSize)
    printTwoCols "Entry Size:" (toHexString section.SecEntrySize)
    printTwoCols "Flag:" (section.SecFlags.ToString ())
    printTwoCols "Link:" (section.SecLink.ToString ())
    printTwoCols "Info:" (section.SecInfo.ToString ())
    printTwoCols "Alignment:" (toHexString section.SecAlignment)
  | None -> Printer.println "Not found."

let printSymbolInfoVerbose (fi: ELFFileInfo) s (elfSymbol: ELF.ELFSymbol) cfg =
  let sectionIndex =
    match elfSymbol.SecHeaderIndex with
    | ELF.SectionHeaderIdx.SecIdx idx -> idx.ToString ()
    | _ as idx -> idx.ToString ()
  Printer.printrow true cfg
    [ targetString s
      addrToString fi.WordSize s.Address
      normalizeEmpty s.Name
      (toLibString >> normalizeEmpty) s.LibraryName
      toHexString elfSymbol.Size
      elfSymbol.SymType.ToString ()
      elfSymbol.Bind.ToString ()
      elfSymbol.Vis.ToString ()
      wrapSqrdBrac sectionIndex ]

let printSymbolInfoNone (fi: ELFFileInfo) s cfg =
  Printer.printrow true cfg
    [ targetString s
      addrToString fi.WordSize s.Address
      normalizeEmpty s.Name
      (toLibString >> normalizeEmpty) s.LibraryName
      "(n/a)"; "(n/a)"; "(n/a)"; "(n/a)"; "(n/a)" ]

let printSymbolInfo isVerbose (fi: ELFFileInfo) (symbols: seq<Symbol>) =
  let addrColumn = columnWidthOfAddr fi |> LeftAligned
  if isVerbose then
    let cfg = [ LeftAligned 4; addrColumn; LeftAligned 55; LeftAligned 15
                LeftAligned 8; LeftAligned 12; LeftAligned 12; LeftAligned 12
                LeftAligned 8 ]
    Printer.printrow true cfg [ "Kind"; "Address"; "Name"; "LibraryName"
                                "Size"; "Type"; "Bind"; "Visibility"
                                "SectionIndex" ]
    Printer.println "  ---"
    symbols
    |> Seq.sortBy (fun s -> s.Name)
    |> Seq.sortBy (fun s -> s.Address)
    |> Seq.sortBy (fun s -> s.Target)
    |> Seq.iter (fun s ->
      match fi.ELF.SymInfo.AddrToSymbTable.TryFind s.Address with
      | Some elfSymbol -> printSymbolInfoVerbose fi s elfSymbol cfg
      | None ->
        match fi.ELF.RelocInfo.RelocByName.TryFind s.Name with
        | Some reloc ->
          match reloc.RelSymbol with
          | Some elfSymbol -> printSymbolInfoVerbose fi s elfSymbol cfg
          | None -> printSymbolInfoNone fi s cfg
        | None -> printSymbolInfoNone fi s cfg)
  else
    let cfg = [ LeftAligned 15; addrColumn; LeftAligned 75; LeftAligned 15 ]
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
          (toLibString >> normalizeEmpty) s.LibraryName ])

let dumpSymbols (opts: FileViewerOpts) (fi: ELFFileInfo) =
  fi.GetSymbols ()
  |> printSymbolInfo opts.Verbose fi

let dumpRelocs (opts: FileViewerOpts) (fi: ELFFileInfo) =
  fi.GetRelocationSymbols ()
  |> printSymbolInfo opts.Verbose fi

let dumpFunctions (opts: FileViewerOpts) (fi: ELFFileInfo) =
  fi.GetFunctionSymbols ()
  |> printSymbolInfo opts.Verbose fi

let dumpSegments (opts: FileViewerOpts) (fi: ELFFileInfo) =
  let addrColumn = columnWidthOfAddr fi |> LeftAligned
  if opts.Verbose then
    let cfg = [ LeftAligned 4; addrColumn; addrColumn; LeftAligned 10
                LeftAligned 12; LeftAligned 8; addrColumn; addrColumn
                LeftAligned 8; LeftAligned 8; LeftAligned 8 ]
    Printer.printrow true cfg [ "Num"; "Start"; "End"; "Permission"
                                "Type"; "Offset"; "VirtAddr"; "PhysAddr"
                                "FileSize"; "MemSize"; "Alignment" ]
    Printer.println "  ---"
    fi.ELF.ProgHeaders
    |> List.iteri (fun idx ph ->
      Printer.printrow true cfg
        [ wrapSqrdBrac (idx.ToString ())
          (addrToString fi.WordSize ph.PHAddr)
          (addrToString fi.WordSize (ph.PHAddr + ph.PHMemSize - uint64 1))
          (FileInfo.PermissionToString ph.PHFlags)
          ph.PHType.ToString ()
          toHexString ph.PHOffset
          toHexString ph.PHAddr
          toHexString ph.PHPhyAddr
          toHexString ph.PHFileSize
          toHexString ph.PHMemSize
          toHexString ph.PHAlignment ])
  else
    let cfg = [ LeftAligned 4; addrColumn; addrColumn; LeftAligned 10 ]
    Printer.printrow true cfg [ "Num"; "Start"; "End"; "Permission" ]
    Printer.println "  ---"
    fi.GetSegments ()
    |> Seq.iteri (fun idx s ->
      Printer.printrow true cfg
        [ wrapSqrdBrac (idx.ToString ())
          (addrToString fi.WordSize s.Address)
          (addrToString fi.WordSize (s.Address + s.Size - uint64 1))
          (FileInfo.PermissionToString s.Permission) ])

let dumpLinkageTable (opts: FileViewerOpts) (fi: ELFFileInfo) =
  let addrColumn = columnWidthOfAddr fi |> LeftAligned
  if opts.Verbose then
    let cfg = [ addrColumn; addrColumn; LeftAligned 40; LeftAligned 15
                LeftAligned 8; LeftAligned 6; LeftAligned 4 ]
    Printer.printrow true cfg [ "PLT Addr"; "GOT Addr"; "FunctionName"; "LibraryName"
                                "Addend"; "SecIdx"; "Type" ]
    Printer.println "  ---"
    fi.GetLinkageTableEntries ()
    |> Seq.iter (fun e ->
      match fi.ELF.RelocInfo.RelocByAddr.TryFind e.TableAddress with
      | Some reloc ->
        Printer.printrow true cfg
          [ (addrToString fi.WordSize e.TrampolineAddress)
            (addrToString fi.WordSize e.TableAddress)
            normalizeEmpty e.FuncName
            (toLibString >> normalizeEmpty) e.LibraryName
            reloc.RelAddend.ToString ()
            reloc.RelSecNumber.ToString ()
            reloc.RelType.ToString () ]
      | None ->
        Printer.printrow true cfg
          [ (addrToString fi.WordSize e.TrampolineAddress)
            (addrToString fi.WordSize e.TableAddress)
            normalizeEmpty e.FuncName
            (toLibString >> normalizeEmpty) e.LibraryName
            "(n/a)"; "(n/a)"; "(n/a)" ])
  else
    let cfg = [ addrColumn; addrColumn; LeftAligned 20; LeftAligned 15 ]
    Printer.printrow true cfg [ "PLT"; "GOT"; "FunctionName"; "LibraryName" ]
    Printer.println "  ---"
    fi.GetLinkageTableEntries ()
    |> Seq.iter (fun e ->
      Printer.printrow true cfg
        [ (addrToString fi.WordSize e.TrampolineAddress)
          (addrToString fi.WordSize e.TableAddress)
          normalizeEmpty e.FuncName
          (toLibString >> normalizeEmpty) e.LibraryName ])

let cfaToString (hdl: BinHandle) cfa =
  ELF.CanonicalFrameAddress.toString hdl.RegisterBay cfa

let ruleToString (hdl: BinHandle) (rule: ELF.Rule) =
  rule
  |> Map.fold (fun s k v ->
    match k with
    | ELF.ReturnAddress -> s + "(ra:" + ELF.Action.toString v + ")"
    | ELF.NormalReg rid ->
      let reg = hdl.RegisterBay.RegIDToString rid
      s + "(" + reg + ":" + ELF.Action.toString v + ")") ""

let dumpEHFrame hdl (fi: ELFFileInfo) =
  let addrColumn = columnWidthOfAddr fi |> LeftAligned
  let cfg = [ addrColumn; LeftAligned 10; LeftAligned 50 ]
  fi.ELF.ExceptionFrame
  |> List.iter (fun cfi ->
    Printer.println ("- CIE: \"{0}\" cf={1} df={2}",
      cfi.CIERecord.AugmentationString,
      cfi.CIERecord.CodeAlignmentFactor.ToString ("+0;-#"),
      cfi.CIERecord.DataAlignmentFactor.ToString ("+0;-#"))
    Printer.println ()
    cfi.FDERecord
    |> Array.iter (fun fde ->
      Printer.println ("  FDE pc={0}..{1}",
        toHexString fde.PCBegin,
        toHexString fde.PCEnd)
      if fde.UnwindingInfo.IsEmpty then ()
      else
        Printer.println "  ---"
        Printer.printrow true cfg [ "Location"; "CFA"; "Rules" ]
      fde.UnwindingInfo
      |> List.iter (fun i ->
        Printer.printrow true cfg
          [ toHexString i.Location
            cfaToString hdl i.CanonicalFrameAddress
            ruleToString hdl i.Rule ])
      Printer.println ()
    )
  )

let dumpNotes hdl (fi: ELFFileInfo) =
  Utils.futureFeature ()
