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
open B2R2.Collections
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.ELF
open B2R2.RearEnd.FileViewer.Helper
open B2R2.RearEnd.Utils

let badAccess _ _ =
  raise InvalidFileFormatException

let computeMagicBytes (file: IBinFile) =
  let span = System.ReadOnlySpan (file.RawBytes, 0, 16)
  span.ToArray () |> ColoredString.ofBytes

let computeEntryPoint (hdr: Header) =
  [ ColoredSegment (Green, HexString.ofUInt64 hdr.EntryPoint) ]

let dumpFileHeader (_: FileViewerOpts) (file: ELFBinFile) =
  let hdr = file.Header
  out.PrintTwoColsWithColorOnSnd "Magic:" (computeMagicBytes file)
  out.PrintTwoCols "Class:" ("ELF" + WordSize.toString hdr.Class)
  out.PrintTwoCols "Data:" (Endian.toString hdr.Endian)
  out.PrintTwoCols "Version:" (hdr.Version.ToString ())
  out.PrintTwoCols "ABI:" (OSABI.toString hdr.OSABI)
  out.PrintTwoCols "ABI version:" (hdr.OSABIVersion.ToString ())
  out.PrintTwoCols "Type:" (ELFType.toString hdr.ELFType)
  out.PrintTwoCols "Machine:" (hdr.MachineType.ToString ())
  out.PrintTwoColsWithColorOnSnd "Entry point:" (computeEntryPoint hdr)
  out.PrintTwoCols "PHdr table offset:" (HexString.ofUInt64 hdr.PHdrTblOffset)
  out.PrintTwoCols "SHdr table offset:" (HexString.ofUInt64 hdr.SHdrTblOffset)
  out.PrintTwoCols "Flags:" (HexString.ofUInt64 (uint64 hdr.ELFFlags))
  out.PrintTwoCols "Header size:" (toNBytes (uint64 hdr.HeaderSize))
  out.PrintTwoCols "PHdr Entry Size:" (toNBytes (uint64 hdr.PHdrEntrySize))
  out.PrintTwoCols "PHdr Entry Num:" (hdr.PHdrNum.ToString ())
  out.PrintTwoCols "SHdr Entry Size:" (toNBytes (uint64 (hdr.SHdrEntrySize)))
  out.PrintTwoCols "SHdr Entry Num:" (hdr.SHdrNum.ToString ())
  out.PrintTwoCols "SHdr string index:" (hdr.SHdrStrIdx.ToString ())

let computeSectionEndAddr (s: SectionHeader) =
  if s.SecSize = 0UL then s.SecAddr
  else s.SecAddr + s.SecSize - 1UL

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
          (Addr.toString file.ISA.WordSize (computeSectionEndAddr s))
          normalizeEmpty s.SecName
          SectionType.toString s.SecType
          HexString.ofUInt64 s.SecOffset
          HexString.ofUInt64 s.SecSize
          HexString.ofUInt64 s.SecEntrySize
          s.SecLink.ToString ()
          s.SecInfo.ToString ()
          HexString.ofUInt64 s.SecAlignment
          normalizeEmpty (SectionFlags.toString s.SecFlags) ]))
  else
    let cfg = [ LeftAligned 4; addrColumn; addrColumn; LeftAligned 24 ]
    out.PrintRow (true, cfg, [ "Num"; "Start"; "End"; "Name" ])
    out.PrintLine "  ---"
    elf.SectionHeaders
    |> Seq.iteri (fun idx s ->
      out.PrintRow (true, cfg,
        [ String.wrapSqrdBracket (idx.ToString ())
          (Addr.toString file.ISA.WordSize s.SecAddr)
          (Addr.toString file.ISA.WordSize (computeSectionEndAddr s))
          normalizeEmpty s.SecName]))

let dumpSectionDetails (secname: string) (file: ELFBinFile) =
  match file.TryFindSection secname with
  | Some section ->
    out.PrintTwoCols "Section number:" (section.SecNum.ToString ())
    out.PrintTwoCols "Section name:" section.SecName
    out.PrintTwoCols "Type:" (SectionType.toString section.SecType)
    out.PrintTwoCols "Address:" (HexString.ofUInt64 section.SecAddr)
    out.PrintTwoCols "Offset:" (HexString.ofUInt64 section.SecOffset)
    out.PrintTwoCols "Size:" (HexString.ofUInt64 section.SecSize)
    out.PrintTwoCols "Entry Size:" (HexString.ofUInt64 section.SecEntrySize)
    out.PrintTwoCols "Flag:" (section.SecFlags.ToString ())
    out.PrintTwoCols "Link:" (section.SecLink.ToString ())
    out.PrintTwoCols "Info:" (section.SecInfo.ToString ())
    out.PrintTwoCols "Alignment:" (HexString.ofUInt64 section.SecAlignment)
  | None -> out.PrintLine "Not found."

let verInfoToString (verInfo: SymVerInfo option) =
  match verInfo with
  | Some version -> (toLibString >> normalizeEmpty) version.VerName
  | None -> ""

let getSectionSymbolName (elf: ELFBinFile) (symb: Symbol) =
  match symb.SymType, symb.SecHeaderIndex with
  | SymbolType.STT_SECTION, SectionIndex idx -> elf.SectionHeaders[idx].SecName
  | _ -> symb.SymName

let printSymbolInfoVerbose (elf: ELFBinFile) (symb: Symbol) vis cfg =
  out.PrintRow (true, cfg,
    [ vis
      Addr.toString (elf :> IBinFile).ISA.WordSize symb.Addr
      getSectionSymbolName elf symb
      verInfoToString symb.VerInfo
      HexString.ofUInt64 symb.Size
      SymbolType.toString symb.SymType
      SymbolBind.toString symb.Bind
      SymbolVisibility.toString symb.Vis
      SectionHeaderIdx.ToString symb.SecHeaderIndex ])

let printSymbolInfoNonVerbose (file: IBinFile) (symb: Symbol) vis cfg =
  out.PrintRow (true, cfg,
    [ vis
      SymbolType.toString symb.SymType
      Addr.toString file.ISA.WordSize symb.Addr
      normalizeEmpty symb.SymName
      normalizeEmpty (verInfoToString symb.VerInfo) ])

let printSymbolInfo isVerbose (elf: ELFBinFile) =
  let addrColumn = columnWidthOfAddr elf |> LeftAligned
  if isVerbose then
    let cfg = [ LeftAligned 4; addrColumn; LeftAligned 55; LeftAligned 15
                LeftAligned 8; LeftAligned 12; LeftAligned 8; LeftAligned 10
                LeftAligned 8 ]
    out.PrintRow (true, cfg, [ "S/D"; "Address"; "Name"; "Lib Name"
                               "Size"; "Type"; "Bind"; "Visibility"
                               "SectionIndex" ])
    out.PrintLine "  ---"
    elf.Symbols.StaticSymbols
    |> Array.iter (fun s -> printSymbolInfoVerbose elf s "(s)" cfg)
    out.PrintLine "  ---"
    elf.Symbols.DynamicSymbols
    |> Array.iter (fun s -> printSymbolInfoVerbose elf s "(d)" cfg)
  else
    let cfg = [ LeftAligned 3; LeftAligned 10
                addrColumn; LeftAligned 75; LeftAligned 15 ]
    out.PrintRow (true, cfg, [ "S/D"; "Kind"; "Address"; "Name"; "Lib Name" ])
    out.PrintLine "  ---"
    elf.Symbols.StaticSymbols
    |> Array.iter (fun s -> printSymbolInfoNonVerbose elf s "(s)" cfg)
    out.PrintLine "  ---"
    elf.Symbols.DynamicSymbols
    |> Array.iter (fun s -> printSymbolInfoNonVerbose elf s "(d)" cfg)

let dumpSymbols (opts: FileViewerOpts) (elf: ELFBinFile) =
  printSymbolInfo opts.Verbose elf

let dumpRelocs (_opts: FileViewerOpts) (elf: ELFBinFile) =
  let addrColumn = columnWidthOfAddr elf |> LeftAligned
  let cfg = [ addrColumn; LeftAligned 24; RightAligned 8; LeftAligned 12 ]
  out.PrintRow (true, cfg, [ "Address"; "Type"; "Addended"; "Symbol" ])
  out.PrintLine "  ---"
  elf.RelocationInfo.Entries
  |> Seq.sortBy (fun reloc -> reloc.RelOffset)
  |> Seq.iter (fun reloc ->
    let symbol =
      match reloc.RelSymbol with
      | Some s when s.SymName.Length > 0 -> s.SymName
      | _ -> "(n/a)"
    out.PrintRow (true, cfg, [
      Addr.toString (elf :> IBinFile).ISA.WordSize reloc.RelOffset
      RelocationKind.ToString reloc.RelKind
      reloc.RelAddend.ToString ("x")
      symbol
    ])
  )

let dumpFunctions (_: FileViewerOpts) (elf: ELFBinFile) =
  let addrColumn = columnWidthOfAddr elf |> LeftAligned
  let cfg = [ LeftAligned 3; LeftAligned 10
              addrColumn; LeftAligned 75; LeftAligned 15 ]
  for addr in (elf :> IBinFile).GetFunctionAddresses () do
    match elf.Symbols.TryFindSymbol addr with
    | Ok symb -> printSymbolInfoNonVerbose elf symb "" cfg
    | Error _ -> ()

let dumpExceptionTable hdl (_opts: FileViewerOpts) (file: ELFBinFile) =
  let exnInfo = ExceptionInfo (hdl=hdl)
  exnInfo.ExceptionMap
  |> NoOverlapIntervalMap.iter (fun range catchBlkAddr ->
    out.PrintLine $"{range.Min:x}:{range.Max:x} -> {catchBlkAddr:x}")

let makeStringTableReader (file: IBinFile) dynEntries =
  dynEntries
  |> Array.fold (fun (addr, len) (ent: DynamicArrayEntry) ->
    match ent.DTag with
    | DTag.DT_STRTAB -> Some ent.DVal, len
    | DTag.DT_STRSZ -> addr, Some ent.DVal
    | _ -> addr, len
  ) (None, None)
  ||> Option.map2 (fun addr len ->
    fun v ->
      let strtab = file.Slice (addr, int len)
      let buf = strtab.Slice (int v)
      ByteArray.extractCStringFromSpan buf 0)

let dumpDynamicSection _ (file: ELFBinFile) =
  let cfg = [ LeftAligned 20; LeftAligned 20 ]
  out.PrintRow (true, cfg, [ "Tag"; "Name/Value" ])
  out.PrintLine "  ---"
  let dynEntries = file.DynamicArrayEntries
  let strtabReader = makeStringTableReader file dynEntries
  dynEntries
  |> Array.iter (fun ent ->
    let tag = ent.DTag
    match tag, strtabReader with
    | DTag.DT_NEEDED, Some reader ->
      out.PrintRow (true, cfg, [ $"{tag}"
                                 $"Shared library: [{reader ent.DVal}]" ])
    | DTag.DT_SONAME, Some reader ->
      out.PrintRow (true, cfg, [ $"{tag}"
                                 $"Library soname: [{reader ent.DVal}]" ])
    | DTag.DT_RPATH, Some reader ->
      out.PrintRow (true, cfg, [ $"{tag}"
                                 $"Library rpath: [{reader ent.DVal}]" ])
    | DTag.DT_RUNPATH, Some reader ->
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
          Addr.toString wordSize ph.PHAddr
          Addr.toString wordSize (ph.PHAddr + ph.PHMemSize - uint64 1)
          Permission.toString (ProgramHeader.FlagsToPerm ph.PHFlags)
          ProgramHeaderType.toString ph.PHType
          HexString.ofUInt64 ph.PHOffset
          Addr.toString wordSize ph.PHAddr
          Addr.toString wordSize ph.PHPhyAddr
          HexString.ofUInt64 ph.PHFileSize
          HexString.ofUInt64 ph.PHMemSize
          HexString.ofUInt64 ph.PHAlignment ]))
  else
    let cfg = [ LeftAligned 4; addrColumn; addrColumn; LeftAligned 10 ]
    out.PrintRow (true, cfg, [ "Num"; "Start"; "End"; "Permission" ])
    out.PrintLine "  ---"
    elf.ProgramHeaders
    |> Array.iteri (fun idx ph ->
      out.PrintRow (true, cfg,
        [ String.wrapSqrdBracket (idx.ToString ())
          (Addr.toString file.ISA.WordSize ph.PHAddr)
          (Addr.toString file.ISA.WordSize (ph.PHAddr + ph.PHMemSize - 1UL))
          (Permission.toString (ProgramHeader.FlagsToPerm ph.PHFlags)) ]))

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
      match elf.RelocationInfo.TryFind e.TableAddress with
      | Ok reloc ->
        out.PrintRow (true, cfg,
          [ (Addr.toString file.ISA.WordSize e.TrampolineAddress)
            (Addr.toString file.ISA.WordSize e.TableAddress)
            normalizeEmpty e.FuncName
            (toLibString >> normalizeEmpty) e.LibraryName
            reloc.RelAddend.ToString ()
            reloc.RelSecNumber.ToString ()
            RelocationKind.ToString reloc.RelKind ])
      | _ ->
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
  CanonicalFrameAddress.ToString (hdl.RegisterFactory, cfa)

let ruleToString (hdl: BinHandle) (rule: UnwindingRule) =
  rule
  |> Map.fold (fun s k v ->
    match k with
    | ReturnAddress -> s + "(ra:" + UnwindingAction.ToString v + ")"
    | NormalReg rid ->
      let reg = hdl.RegisterFactory.GetRegString rid
      s + "(" + reg + ":" + UnwindingAction.ToString v + ")") ""

let dumpEHFrame hdl (file: ELFBinFile) =
  let addrColumn = columnWidthOfAddr file |> LeftAligned
  let cfg = [ addrColumn; LeftAligned 10; LeftAligned 50 ]
  file.ExceptionFrame
  |> List.iter (fun cfi ->
    out.PrintLine ("- CIE: \"{0}\" cf={1} df={2}",
      cfi.CIE.AugmentationString,
      cfi.CIE.CodeAlignmentFactor.ToString ("+0;-#"),
      cfi.CIE.DataAlignmentFactor.ToString ("+0;-#"))
    out.PrintLine ()
    for fde in cfi.FDEs do
      out.PrintLine ("  FDE pc={0}..{1}",
        HexString.ofUInt64 fde.PCBegin,
        HexString.ofUInt64 fde.PCEnd)
      if fde.UnwindingInfo.IsEmpty then ()
      else
        out.PrintLine "  ---"
        out.PrintRow (true, cfg, [ "Location"; "CFA"; "Rules" ])
      fde.UnwindingInfo
      |> List.iter (fun i ->
        out.PrintRow (true, cfg,
          [ HexString.ofUInt64 i.Location
            cfaToString hdl i.CanonicalFrameAddress
            ruleToString hdl i.Rule ]))
      out.PrintLine ()
  )

let dumpGccExceptTable _hdl (elf: ELFBinFile) =
  let addrColumn = columnWidthOfAddr elf |> LeftAligned
  let file = elf :> IBinFile
  let cfg = [ addrColumn; LeftAligned 15; LeftAligned 15; addrColumn ]
  out.PrintRow (true, cfg, [ "Address"; "LP App"; "LP Val"; "TT End" ])
  elf.LSDATable
  |> Map.iter (fun lsdaAddr lsda ->
    let ttbase = lsda.TTBase |> Option.defaultValue 0UL
    out.PrintRow (true, cfg,
      [ Addr.toString file.ISA.WordSize lsdaAddr
        lsda.LPAppEncoding.ToString ()
        lsda.LPValueEncoding.ToString ()
        ttbase |> Addr.toString file.ISA.WordSize ])
  )

let dumpNotes _hdl (file: ELFBinFile) =
  Terminator.futureFeature ()
