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
open B2R2.FrontEnd.BinFile.ELF
open B2R2.RearEnd.FileViewer.Helper
open B2R2.MiddleEnd.ControlFlowAnalysis

let badAccess _ _ =
  raise InvalidFileFormatException

let computeMagicBytes (file: IBinFile) =
  let slice = file.Slice (offset=0, size=16)
  slice.ToArray () |> ColoredSegment.colorBytes

let computeEntryPoint (hdr: ELFHeader) =
  [ ColoredSegment.green <| String.u64ToHex hdr.EntryPoint ]

let dumpFileHeader (_: FileViewerOpts) (file: ELFBinFile) =
  let hdr = file.Header
  out.PrintTwoColsWithColorOnSnd "Magic:" (computeMagicBytes file)
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

let dumpSectionHeaders (opts: FileViewerOpts) (elf: ELFBinFile) =
  let addrColumn = columnWidthOfAddr elf |> LeftAligned
  let file = elf :> IBinFile
  if opts.Verbose then
    let cfg = [ LeftAligned 4; addrColumn; addrColumn; LeftAligned 24;
                LeftAligned 14; LeftAligned 12; LeftAligned 8; LeftAligned 10;
                LeftAligned 4; LeftAligned 4; LeftAligned 6; LeftAligned 20 ]
    out.PrintRow (true, cfg, [ "Num"; "Start"; "End"; "Name"
                               "Type"; "Offset"; "Size"; "EntrySize"
                               "Link"; "Info"; "Align"; "Flags" ])
    out.PrintLine "  ---"
    elf.SectionHeaders
    |> Array.iteri (fun idx s ->
      out.PrintRow (true, cfg,
        [ String.wrapSqrdBracket (idx.ToString ())
          (Addr.toString file.ISA.WordSize s.SecAddr)
          (Addr.toString file.ISA.WordSize (s.SecAddr + s.SecSize - uint64 1))
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
    file.GetSections ()
    |> Seq.iteri (fun idx s ->
      out.PrintRow (true, cfg,
        [ String.wrapSqrdBracket (idx.ToString ())
          (Addr.toString file.ISA.WordSize s.Address)
          (Addr.toString file.ISA.WordSize (s.Address + uint64 s.Size - 1UL))
          normalizeEmpty s.Name ]))

let dumpSectionDetails (secname: string) (file: ELFBinFile) =
  match file.TryFindSection secname with
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

let printSymbolInfoVerbose (file: IBinFile) s (elfSymbol: ELFSymbol) cfg =
  let sectionIndex =
    match elfSymbol.SecHeaderIndex with
    | SecIdx idx -> idx.ToString ()
    | idx -> idx.ToString ()
  out.PrintRow (true, cfg,
    [ visibilityString s
      Addr.toString file.ISA.WordSize s.Address
      normalizeEmpty s.Name
      (toLibString >> normalizeEmpty) s.LibraryName
      String.u64ToHex elfSymbol.Size
      elfSymbol.SymType.ToString ()
      elfSymbol.Bind.ToString ()
      elfSymbol.Vis.ToString ()
      String.wrapSqrdBracket sectionIndex ])

let printSymbolInfoNone (file: IBinFile) s cfg =
  out.PrintRow (true, cfg,
    [ visibilityString s
      Addr.toString file.ISA.WordSize s.Address
      normalizeEmpty s.Name
      (toLibString >> normalizeEmpty) s.LibraryName
      "(n/a)"; "(n/a)"; "(n/a)"; "(n/a)"; "(n/a)" ])

let printSymbolInfo isVerbose (elf: ELFBinFile) (symbols: seq<Symbol>) =
  let addrColumn = columnWidthOfAddr elf |> LeftAligned
  if isVerbose then
    let cfg = [ LeftAligned 4; addrColumn; LeftAligned 55; LeftAligned 15
                LeftAligned 8; LeftAligned 12; LeftAligned 12; LeftAligned 12
                LeftAligned 8 ]
    out.PrintRow (true, cfg, [ "S/D"; "Address"; "Name"; "Lib Name"
                               "Size"; "Type"; "Bind"; "Visibility"
                               "SectionIndex" ])
    out.PrintLine "  ---"
    symbols
    |> Seq.sortBy (fun s -> s.Name)
    |> Seq.sortBy (fun s -> s.Address)
    |> Seq.sortBy (fun s -> s.Visibility)
    |> Seq.iter (fun s ->
      match elf.SymbolInfo.AddrToSymbTable.TryGetValue s.Address with
      | true, elfSymbol -> printSymbolInfoVerbose elf s elfSymbol cfg
      | false, _ ->
        match elf.RelocationInfo.RelocByName.TryGetValue s.Name with
        | true, reloc ->
          match reloc.RelSymbol with
          | Some elfSymbol -> printSymbolInfoVerbose elf s elfSymbol cfg
          | None -> printSymbolInfoNone elf s cfg
        | false, _ -> printSymbolInfoNone elf s cfg)
  else
    let cfg = [ LeftAligned 3; LeftAligned 10
                addrColumn; LeftAligned 75; LeftAligned 15 ]
    out.PrintRow (true, cfg, [ "S/D"; "Kind"; "Address"; "Name"; "Lib Name" ])
    out.PrintLine "  ---"
    symbols
    |> Seq.sortBy (fun s -> s.Name)
    |> Seq.sortBy (fun s -> s.Address)
    |> Seq.sortBy (fun s -> s.Visibility)
    |> Seq.iter (fun s ->
      out.PrintRow (true, cfg,
        [ visibilityString s
          symbolKindString s
          Addr.toString (elf :> IBinFile).ISA.WordSize s.Address
          normalizeEmpty s.Name
          (toLibString >> normalizeEmpty) s.LibraryName ]))

let dumpSymbols (opts: FileViewerOpts) (elf: ELFBinFile) =
  (elf :> IBinFile).GetSymbols ()
  |> printSymbolInfo opts.Verbose elf

let dumpRelocs (_opts: FileViewerOpts) (elf: ELFBinFile) =
  let addrColumn = columnWidthOfAddr elf |> LeftAligned
  let cfg = [ addrColumn; LeftAligned 24; RightAligned 8; LeftAligned 12 ]
  out.PrintRow (true, cfg, [ "Address"; "Type"; "Addended"; "Symbol" ])
  out.PrintLine "  ---"
  elf.RelocationInfo.RelocByAddr.Values
  |> Seq.sortBy (fun reloc -> reloc.RelOffset)
  |> Seq.iter (fun reloc ->
    let symbol =
      match reloc.RelSymbol with
      | Some s when s.SymName.Length > 0 -> s.SymName
      | _ -> "(n/a)"
    out.PrintRow (true, cfg, [
      Addr.toString (elf :> IBinFile).ISA.WordSize reloc.RelOffset
      RelocationType.ToString reloc.RelType
      reloc.RelAddend.ToString ("x")
      symbol
    ])
  )

let dumpFunctions (opts: FileViewerOpts) (elf: ELFBinFile) =
  (elf :> IBinFile).GetFunctionSymbols ()
  |> printSymbolInfo opts.Verbose elf

let dumpExceptionTable hdl (_opts: FileViewerOpts) (file: ELFBinFile) =
  let exnTbl, _ = ELFExceptionTable.build hdl file
  exnTbl
  |> ARMap.iter (fun range catchBlkAddr ->
    out.PrintLine $"{range.Min:x}:{range.Max:x} -> {catchBlkAddr:x}")

let makeStringTableReader (file: IBinFile) dynEntries =
  dynEntries
  |> Array.fold (fun (addr, len) (ent: DynamicSectionEntry) ->
    match ent.DTag with
    | DynamicTag.DT_STRTAB -> Some ent.DVal, len
    | DynamicTag.DT_STRSZ -> addr, Some ent.DVal
    | _ -> addr, len
  ) (None, None)
  ||> Option.map2 (fun addr len ->
    fun v ->
      let strtab = file.Slice (addr=addr, size=int len)
      let buf = strtab.Slice (int v)
      ByteArray.extractCStringFromSpan buf 0)

let dumpDynamicSection _ (file: ELFBinFile) =
  let cfg = [ LeftAligned 20; LeftAligned 20 ]
  out.PrintRow (true, cfg, [ "Tag"; "Name/Value" ])
  out.PrintLine "  ---"
  let dynEntries = file.DynamicSectionEntries
  let strtabReader = makeStringTableReader file dynEntries
  dynEntries
  |> Array.iter (fun ent ->
    let tag = ent.DTag
    match tag, strtabReader with
    | DynamicTag.DT_NEEDED, Some reader ->
      out.PrintRow (true, cfg, [ $"{tag}"
                                 $"Shared library: [{reader ent.DVal}]" ])
    | DynamicTag.DT_SONAME, Some reader ->
      out.PrintRow (true, cfg, [ $"{tag}"
                                 $"Library soname: [{reader ent.DVal}]" ])
    | DynamicTag.DT_RPATH, Some reader ->
      out.PrintRow (true, cfg, [ $"{tag}"
                                 $"Library rpath: [{reader ent.DVal}]" ])
    | DynamicTag.DT_RUNPATH, Some reader ->
      out.PrintRow (true, cfg, [ $"{tag}"
                                 $"Library runpath: [{reader ent.DVal}]" ])
    | _ ->
      out.PrintRow (true, cfg, [ $"{tag}"; "0x" + ent.DVal.ToString "x" ])
  )

let dumpSegments (opts: FileViewerOpts) (elf: ELFBinFile) =
  let addrColumn = columnWidthOfAddr elf |> LeftAligned
  let file = elf :> IBinFile
  if opts.Verbose then
    let cfg = [ LeftAligned 4; addrColumn; addrColumn; LeftAligned 10
                LeftAligned 12; LeftAligned 8; addrColumn; addrColumn
                LeftAligned 8; LeftAligned 8; LeftAligned 8 ]
    out.PrintRow (true, cfg, [ "Num"; "Start"; "End"; "Permission"
                               "Type"; "Offset"; "VirtAddr"; "PhysAddr"
                               "FileSize"; "MemSize"; "Alignment" ])
    out.PrintLine "  ---"
    let wordSize = file.ISA.WordSize
    elf.ProgramHeaders
    |> Array.iteri (fun idx ph ->
      out.PrintRow (true, cfg,
        [ String.wrapSqrdBracket (idx.ToString ())
          (Addr.toString wordSize ph.PHAddr)
          (Addr.toString wordSize (ph.PHAddr + ph.PHMemSize - uint64 1))
          (Permission.toString ph.PHFlags)
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
    file.GetSegments ()
    |> Seq.iteri (fun idx s ->
      out.PrintRow (true, cfg,
        [ String.wrapSqrdBracket (idx.ToString ())
          (Addr.toString file.ISA.WordSize s.Address)
          (Addr.toString file.ISA.WordSize (s.Address + uint64 s.Size - 1UL))
          (Permission.toString s.Permission) ]))

let dumpLinkageTable (opts: FileViewerOpts) (elf: ELFBinFile) =
  let addrColumn = columnWidthOfAddr elf |> LeftAligned
  let file = elf :> IBinFile
  if opts.Verbose then
    let cfg = [ addrColumn; addrColumn; LeftAligned 40; LeftAligned 15
                LeftAligned 8; LeftAligned 6; LeftAligned 4 ]
    out.PrintRow (true, cfg,
      [ "PLT Addr"; "GOT Addr"; "FunctionName"; "Lib Name"
        "Addend"; "SecIdx"; "Type" ])
    out.PrintLine "  ---"
    file.GetLinkageTableEntries ()
    |> Seq.iter (fun e ->
      match elf.RelocationInfo.RelocByAddr.TryGetValue e.TableAddress with
      | true, reloc ->
        out.PrintRow (true, cfg,
          [ (Addr.toString file.ISA.WordSize e.TrampolineAddress)
            (Addr.toString file.ISA.WordSize e.TableAddress)
            normalizeEmpty e.FuncName
            (toLibString >> normalizeEmpty) e.LibraryName
            reloc.RelAddend.ToString ()
            reloc.RelSecNumber.ToString ()
            reloc.RelType.ToString () ])
      | false, _ ->
        out.PrintRow (true, cfg,
          [ (Addr.toString file.ISA.WordSize e.TrampolineAddress)
            (Addr.toString file.ISA.WordSize e.TableAddress)
            normalizeEmpty e.FuncName
            (toLibString >> normalizeEmpty) e.LibraryName
            "(n/a)"; "(n/a)"; "(n/a)" ]))
  else
    let cfg = [ addrColumn; addrColumn; LeftAligned 20; LeftAligned 15 ]
    out.PrintRow (true, cfg,
      [ "PLT"; "GOT"; "FunctionName"; "Lib Name" ])
    out.PrintLine "  ---"
    file.GetLinkageTableEntries ()
    |> Seq.iter (fun e ->
      out.PrintRow (true, cfg,
        [ (Addr.toString file.ISA.WordSize e.TrampolineAddress)
          (Addr.toString file.ISA.WordSize e.TableAddress)
          normalizeEmpty e.FuncName
          (toLibString >> normalizeEmpty) e.LibraryName ]))

let cfaToString (hdl: BinHandle) cfa =
  CanonicalFrameAddress.toString hdl.RegisterBay cfa

let ruleToString (hdl: BinHandle) (rule: Rule) =
  rule
  |> Map.fold (fun s k v ->
    match k with
    | ReturnAddress -> s + "(ra:" + Action.toString v + ")"
    | NormalReg rid ->
      let reg = hdl.RegisterBay.RegIDToString rid
      s + "(" + reg + ":" + Action.toString v + ")") ""

let dumpEHFrame hdl (file: ELFBinFile) =
  let addrColumn = columnWidthOfAddr file |> LeftAligned
  let cfg = [ addrColumn; LeftAligned 10; LeftAligned 50 ]
  file.ExceptionInfo.ExceptionFrames
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

let dumpGccExceptTable _hdl (elf: ELFBinFile) =
  let addrColumn = columnWidthOfAddr elf |> LeftAligned
  let file = elf :> IBinFile
  let cfg = [ addrColumn; LeftAligned 15; LeftAligned 15; addrColumn ]
  out.PrintRow (true, cfg, [ "Address"; "LP App"; "LP Val"; "TT End" ])
  elf.ExceptionInfo.LSDAs
  |> Map.iter (fun lsdaAddr lsda ->
    let ttbase = lsda.Header.TTBase |> Option.defaultValue 0UL
    out.PrintRow (true, cfg,
      [ Addr.toString file.ISA.WordSize lsdaAddr
        lsda.Header.LPAppEncoding.ToString ()
        lsda.Header.LPValueEncoding.ToString ()
        ttbase |> Addr.toString file.ISA.WordSize ])
  )

let dumpNotes _hdl (file: ELFBinFile) =
  Utils.futureFeature ()
