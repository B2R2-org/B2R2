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
open B2R2.RearEnd.FileViewer.Helper

let badAccess _ _ =
  raise InvalidFileTypeException

let computeMagicBytes (fi: ELFFileInfo) =
  fi.ELF.BinReader.ReadBytes (fi.Span, 0, 16) |> ColoredSegment.colorBytes

let computeEntryPoint (hdr: ELF.ELFHeader) =
  [ ColoredSegment.green <| String.u64ToHex hdr.EntryPoint ]

let dumpFileHeader (_: FileViewerOpts) (fi: ELFFileInfo) =
  let hdr = fi.ELF.ELFHdr
  out.PrintTwoColsWithColorOnSnd "Magic:" (computeMagicBytes fi)
  out.PrintTwoCols "Class:" ("ELF" + WordSize.toString hdr.Class)
  out.PrintTwoCols "Data:" (Endian.toString hdr.Endian + " endian")
  out.PrintTwoCols "Version:" (hdr.Version.ToString ())
  out.PrintTwoCols "ABI:" (hdr.OSABI.ToString ())
  out.PrintTwoCols "ABI version:" (hdr.OSABIVersion.ToString ())
  out.PrintTwoCols "Type:" (hdr.ELFFileType.ToString ())
  out.PrintTwoCols "Machine:" (hdr.MachineType.ToString ())
  out.PrintTwoColsWithColorOnSnd "Entry point:" (computeEntryPoint hdr)
  out.PrintTwoCols "PHdr table offset:" (String.u64ToHex hdr.PHdrTblOffset)
  out.PrintTwoCols "SHdr table offset:" (String.u64ToHex hdr.SHdrTblOffset)
  out.PrintTwoCols "Flags:" (String.u64ToHex (uint64 hdr.ELFFlags))
  out.PrintTwoCols "Header size:" (toNBytes (uint64 hdr.HeaderSize))
  out.PrintTwoCols "PHdr Entry Size:" (toNBytes (uint64 hdr.PHdrEntrySize))
  out.PrintTwoCols "PHdr Entry Num:" (hdr.PHdrNum.ToString ())
  out.PrintTwoCols "SHdr Entry Size:" (toNBytes (uint64 (hdr.SHdrEntrySize)))
  out.PrintTwoCols "SHdr Entry Num:" (hdr.SHdrNum.ToString ())
  out.PrintTwoCols "SHdr string index:" (hdr.SHdrStrIdx.ToString ())

let dumpSectionHeaders (opts: FileViewerOpts) (fi: ELFFileInfo) =
  let addrColumn = columnWidthOfAddr fi |> LeftAligned
  if opts.Verbose then
    let cfg = [ LeftAligned 4; addrColumn; addrColumn; LeftAligned 24;
                LeftAligned 14; LeftAligned 12; LeftAligned 8; LeftAligned 10;
                LeftAligned 4; LeftAligned 4; LeftAligned 6; LeftAligned 20 ]
    out.PrintRow (true, cfg, [ "Num"; "Start"; "End"; "Name"
                               "Type"; "Offset"; "Size"; "EntrySize"
                               "Link"; "Info"; "Align"; "Flags" ])
    out.PrintLine "  ---"
    fi.ELF.SecInfo.SecByNum
    |> Array.iteri (fun idx s ->
      out.PrintRow (true, cfg,
        [ String.wrapSqrdBracket (idx.ToString ())
          (Addr.toString fi.WordSize s.SecAddr)
          (Addr.toString fi.WordSize (s.SecAddr + s.SecSize - uint64 1))
          normalizeEmpty s.SecName
          s.SecType.ToString ()
          String.u64ToHex s.SecOffset
          String.u64ToHex s.SecSize
          String.u64ToHex s.SecEntrySize
          s.SecLink.ToString ()
          s.SecInfo.ToString ()
          String.u64ToHex s.SecAlignment
          s.SecFlags.ToString () ]))
  else
    let cfg = [ LeftAligned 4; addrColumn; addrColumn; LeftAligned 24 ]
    out.PrintRow (true, cfg, [ "Num"; "Start"; "End"; "Name" ])
    out.PrintLine "  ---"
    fi.GetSections ()
    |> Seq.iteri (fun idx s ->
      out.PrintRow (true, cfg,
        [ String.wrapSqrdBracket (idx.ToString ())
          (Addr.toString fi.WordSize s.Address)
          (Addr.toString fi.WordSize (s.Address + s.Size - uint64 1))
          normalizeEmpty s.Name ]))

let dumpSectionDetails (secname: string) (fi: ELFFileInfo) =
  match fi.ELF.SecInfo.SecByName.TryFind secname with
  | Some section ->
    out.PrintTwoCols "Section number:" (section.SecNum.ToString ())
    out.PrintTwoCols "Section name:" section.SecName
    out.PrintTwoCols "Type:" (section.SecType.ToString ())
    out.PrintTwoCols "Address:" (String.u64ToHex section.SecAddr)
    out.PrintTwoCols "Offset:" (String.u64ToHex section.SecOffset)
    out.PrintTwoCols "Size:" (String.u64ToHex section.SecSize)
    out.PrintTwoCols "Entry Size:" (String.u64ToHex section.SecEntrySize)
    out.PrintTwoCols "Flag:" (section.SecFlags.ToString ())
    out.PrintTwoCols "Link:" (section.SecLink.ToString ())
    out.PrintTwoCols "Info:" (section.SecInfo.ToString ())
    out.PrintTwoCols "Alignment:" (String.u64ToHex section.SecAlignment)
  | None -> out.PrintLine "Not found."

let printSymbolInfoVerbose (fi: ELFFileInfo) s (elfSymbol: ELF.ELFSymbol) cfg =
  let sectionIndex =
    match elfSymbol.SecHeaderIndex with
    | ELF.SectionHeaderIdx.SecIdx idx -> idx.ToString ()
    | _ as idx -> idx.ToString ()
  out.PrintRow (true, cfg,
    [ targetString s
      Addr.toString fi.WordSize s.Address
      normalizeEmpty s.Name
      (toLibString >> normalizeEmpty) s.LibraryName
      String.u64ToHex elfSymbol.Size
      elfSymbol.SymType.ToString ()
      elfSymbol.Bind.ToString ()
      elfSymbol.Vis.ToString ()
      String.wrapSqrdBracket sectionIndex ])

let printSymbolInfoNone (fi: ELFFileInfo) s cfg =
  out.PrintRow (true, cfg,
    [ targetString s
      Addr.toString fi.WordSize s.Address
      normalizeEmpty s.Name
      (toLibString >> normalizeEmpty) s.LibraryName
      "(n/a)"; "(n/a)"; "(n/a)"; "(n/a)"; "(n/a)" ])

let printSymbolInfo isVerbose (fi: ELFFileInfo) (symbols: seq<Symbol>) =
  let addrColumn = columnWidthOfAddr fi |> LeftAligned
  if isVerbose then
    let cfg = [ LeftAligned 4; addrColumn; LeftAligned 55; LeftAligned 15
                LeftAligned 8; LeftAligned 12; LeftAligned 12; LeftAligned 12
                LeftAligned 8 ]
    out.PrintRow (true, cfg, [ "Kind"; "Address"; "Name"; "LibraryName"
                               "Size"; "Type"; "Bind"; "Visibility"
                               "SectionIndex" ])
    out.PrintLine "  ---"
    symbols
    |> Seq.sortBy (fun s -> s.Name)
    |> Seq.sortBy (fun s -> s.Address)
    |> Seq.sortBy (fun s -> s.Target)
    |> Seq.iter (fun s ->
      match fi.ELF.SymInfo.AddrToSymbTable.TryFind s.Address with
      | Some elfSymbol -> printSymbolInfoVerbose fi s elfSymbol cfg
      | None ->
        match fi.ELF.RelocInfo.RelocByName.TryGetValue s.Name with
        | true, reloc ->
          match reloc.RelSymbol with
          | Some elfSymbol -> printSymbolInfoVerbose fi s elfSymbol cfg
          | None -> printSymbolInfoNone fi s cfg
        | false, _ -> printSymbolInfoNone fi s cfg)
  else
    let cfg = [ LeftAligned 15; addrColumn; LeftAligned 75; LeftAligned 15 ]
    out.PrintRow (true, cfg, [ "Kind"; "Address"; "Name"; "LibraryName" ])
    out.PrintLine "  ---"
    symbols
    |> Seq.sortBy (fun s -> s.Name)
    |> Seq.sortBy (fun s -> s.Address)
    |> Seq.sortBy (fun s -> s.Target)
    |> Seq.iter (fun s ->
      out.PrintRow (true, cfg,
        [ targetString s
          Addr.toString fi.WordSize s.Address
          normalizeEmpty s.Name
          (toLibString >> normalizeEmpty) s.LibraryName ]))

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
    out.PrintRow (true, cfg, [ "Num"; "Start"; "End"; "Permission"
                               "Type"; "Offset"; "VirtAddr"; "PhysAddr"
                               "FileSize"; "MemSize"; "Alignment" ])
    out.PrintLine "  ---"
    fi.ELF.ProgHeaders
    |> List.iteri (fun idx ph ->
      out.PrintRow (true, cfg,
        [ String.wrapSqrdBracket (idx.ToString ())
          (Addr.toString fi.WordSize ph.PHAddr)
          (Addr.toString fi.WordSize (ph.PHAddr + ph.PHMemSize - uint64 1))
          (FileInfo.PermissionToString ph.PHFlags)
          ph.PHType.ToString ()
          String.u64ToHex ph.PHOffset
          String.u64ToHex ph.PHAddr
          String.u64ToHex ph.PHPhyAddr
          String.u64ToHex ph.PHFileSize
          String.u64ToHex ph.PHMemSize
          String.u64ToHex ph.PHAlignment ]))
  else
    let cfg = [ LeftAligned 4; addrColumn; addrColumn; LeftAligned 10 ]
    out.PrintRow (true, cfg, [ "Num"; "Start"; "End"; "Permission" ])
    out.PrintLine "  ---"
    fi.GetSegments ()
    |> Seq.iteri (fun idx s ->
      out.PrintRow (true, cfg,
        [ String.wrapSqrdBracket (idx.ToString ())
          (Addr.toString fi.WordSize s.Address)
          (Addr.toString fi.WordSize (s.Address + s.Size - uint64 1))
          (FileInfo.PermissionToString s.Permission) ]))

let dumpLinkageTable (opts: FileViewerOpts) (fi: ELFFileInfo) =
  let addrColumn = columnWidthOfAddr fi |> LeftAligned
  if opts.Verbose then
    let cfg = [ addrColumn; addrColumn; LeftAligned 40; LeftAligned 15
                LeftAligned 8; LeftAligned 6; LeftAligned 4 ]
    out.PrintRow (true, cfg,
      [ "PLT Addr"; "GOT Addr"; "FunctionName"; "LibraryName"
        "Addend"; "SecIdx"; "Type" ])
    out.PrintLine "  ---"
    fi.GetLinkageTableEntries ()
    |> Seq.iter (fun e ->
      match fi.ELF.RelocInfo.RelocByAddr.TryGetValue e.TableAddress with
      | true, reloc ->
        out.PrintRow (true, cfg,
          [ (Addr.toString fi.WordSize e.TrampolineAddress)
            (Addr.toString fi.WordSize e.TableAddress)
            normalizeEmpty e.FuncName
            (toLibString >> normalizeEmpty) e.LibraryName
            reloc.RelAddend.ToString ()
            reloc.RelSecNumber.ToString ()
            reloc.RelType.ToString () ])
      | false, _ ->
        out.PrintRow (true, cfg,
          [ (Addr.toString fi.WordSize e.TrampolineAddress)
            (Addr.toString fi.WordSize e.TableAddress)
            normalizeEmpty e.FuncName
            (toLibString >> normalizeEmpty) e.LibraryName
            "(n/a)"; "(n/a)"; "(n/a)" ]))
  else
    let cfg = [ addrColumn; addrColumn; LeftAligned 20; LeftAligned 15 ]
    out.PrintRow (true, cfg,
      [ "PLT"; "GOT"; "FunctionName"; "LibraryName" ])
    out.PrintLine "  ---"
    fi.GetLinkageTableEntries ()
    |> Seq.iter (fun e ->
      out.PrintRow (true, cfg,
        [ (Addr.toString fi.WordSize e.TrampolineAddress)
          (Addr.toString fi.WordSize e.TableAddress)
          normalizeEmpty e.FuncName
          (toLibString >> normalizeEmpty) e.LibraryName ]))

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
    out.PrintLine ("- CIE: \"{0}\" cf={1} df={2}",
      cfi.CIERecord.AugmentationString,
      cfi.CIERecord.CodeAlignmentFactor.ToString ("+0;-#"),
      cfi.CIERecord.DataAlignmentFactor.ToString ("+0;-#"))
    out.PrintLine ()
    cfi.FDERecord
    |> Array.iter (fun fde ->
      out.PrintLine ("  FDE pc={0}..{1}",
        String.u64ToHex fde.PCBegin,
        String.u64ToHex fde.PCEnd)
      if fde.UnwindingInfo.IsEmpty then ()
      else
        out.PrintLine "  ---"
        out.PrintRow (true, cfg, [ "Location"; "CFA"; "Rules" ])
      fde.UnwindingInfo
      |> List.iter (fun i ->
        out.PrintRow (true, cfg,
          [ String.u64ToHex i.Location
            cfaToString hdl i.CanonicalFrameAddress
            ruleToString hdl i.Rule ]))
      out.PrintLine ()
    )
  )

let dumpLSDA _hdl (fi: ELFFileInfo) =
  let addrColumn = columnWidthOfAddr fi |> LeftAligned
  let cfg = [ addrColumn; LeftAligned 15; LeftAligned 15; addrColumn ]
  out.PrintRow (true, cfg, [ "Address"; "LP App"; "LP Val"; "TT End" ])
  fi.ELF.LSDAs
  |> Map.iter (fun lsdaAddr lsda ->
    let ttbase = lsda.Header.TTBase |> Option.defaultValue 0UL
    out.PrintRow (true, cfg,
      [ Addr.toString fi.WordSize lsdaAddr
        lsda.Header.LPAppEncoding.ToString ()
        lsda.Header.LPValueEncoding.ToString ()
        ttbase |> Addr.toString fi.WordSize ])
  )

let dumpNotes _hdl (fi: ELFFileInfo) =
  Utils.futureFeature ()
