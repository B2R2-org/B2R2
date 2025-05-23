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
open B2R2.RearEnd.FileViewer.Helper
open B2R2.RearEnd.Utils

let badAccess _ _ =
  raise InvalidFileFormatException

let computeMagicBytes (file: IBinFile) =
  let span = System.ReadOnlySpan (file.RawBytes, 0, 16)
  span.ToArray () |> ColoredString.ofBytes

let computeEntryPoint (hdr: ELF.Header) =
  [ ColoredSegment (Green, HexString.ofUInt64 hdr.EntryPoint) ]

let dumpFileHeader (_: FileViewerOpts) (file: ELFBinFile) =
  let hdr = file.Header
  out.PrintTwoColsWithColorOnSnd "Magic:" (computeMagicBytes file)
  out.PrintTwoCols "Class:" ("ELF" + WordSize.toString hdr.Class)
  out.PrintTwoCols "Data:" (Endian.toString hdr.Endian + " endian")
  out.PrintTwoCols "Version:" (hdr.Version.ToString ())
  out.PrintTwoCols "ABI:" (ELF.OSABI.toString hdr.OSABI)
  out.PrintTwoCols "ABI version:" (hdr.OSABIVersion.ToString ())
  out.PrintTwoCols "Type:" (ELF.ELFType.toString hdr.ELFType)
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
          HexString.ofUInt64 s.SecOffset
          HexString.ofUInt64 s.SecSize
          HexString.ofUInt64 s.SecEntrySize
          s.SecLink.ToString ()
          s.SecInfo.ToString ()
          HexString.ofUInt64 s.SecAlignment
          s.SecFlags.ToString () ]))
  else
    let cfg = [ LeftAligned 4; addrColumn; addrColumn; LeftAligned 24 ]
    out.PrintRow (true, cfg, [ "Num"; "Start"; "End"; "Name" ])
    out.PrintLine "  ---"
    elf.SectionHeaders
    |> Seq.iteri (fun idx s ->
      out.PrintRow (true, cfg,
        [ String.wrapSqrdBracket (idx.ToString ())
          (Addr.toString file.ISA.WordSize s.SecAddr)
          (Addr.toString file.ISA.WordSize (s.SecAddr + uint64 s.SecSize - 1UL))
          normalizeEmpty s.SecName]))

let dumpSectionDetails (secname: string) (file: ELFBinFile) =
  match file.TryFindSection secname with
  | Some section ->
    out.PrintTwoCols "Section number:" (section.SecNum.ToString ())
    out.PrintTwoCols "Section name:" section.SecName
    out.PrintTwoCols "Type:" (section.SecType.ToString ())
    out.PrintTwoCols "Address:" (HexString.ofUInt64 section.SecAddr)
    out.PrintTwoCols "Offset:" (HexString.ofUInt64 section.SecOffset)
    out.PrintTwoCols "Size:" (HexString.ofUInt64 section.SecSize)
    out.PrintTwoCols "Entry Size:" (HexString.ofUInt64 section.SecEntrySize)
    out.PrintTwoCols "Flag:" (section.SecFlags.ToString ())
    out.PrintTwoCols "Link:" (section.SecLink.ToString ())
    out.PrintTwoCols "Info:" (section.SecInfo.ToString ())
    out.PrintTwoCols "Alignment:" (HexString.ofUInt64 section.SecAlignment)
  | None -> out.PrintLine "Not found."

let verInfoToString (verInfo: ELF.SymVerInfo option) =
  match verInfo with
  | Some version -> (toLibString >> normalizeEmpty) version.VerName
  | None -> ""

let printSymbolInfoVerbose (file: IBinFile) (symb: ELF.ELFSymbol) vis cfg =
  let sectionIndex =
    match symb.SecHeaderIndex with
    | ELF.SectionIndex idx -> idx.ToString ()
    | idx -> idx.ToString ()
  out.PrintRow (true, cfg,
    [ vis
      Addr.toString file.ISA.WordSize symb.Addr
      normalizeEmpty symb.SymName
      verInfoToString symb.VerInfo
      HexString.ofUInt64 symb.Size
      symb.SymType.ToString ()
      symb.Bind.ToString ()
      symb.Vis.ToString ()
      String.wrapSqrdBracket sectionIndex ])

let printSymbolInfoNonVerbose (file: IBinFile) (symb: ELF.ELFSymbol) vis cfg =
  out.PrintRow (true, cfg,
    [ vis
      $"{symb.SymType}"
      Addr.toString file.ISA.WordSize symb.Addr
      normalizeEmpty symb.SymName
      verInfoToString symb.VerInfo ])

let printSymbolInfo isVerbose (elf: ELFBinFile) =
  let addrColumn = columnWidthOfAddr elf |> LeftAligned
  if isVerbose then
    let cfg = [ LeftAligned 4; addrColumn; LeftAligned 55; LeftAligned 15
                LeftAligned 8; LeftAligned 12; LeftAligned 12; LeftAligned 12
                LeftAligned 8 ]
    out.PrintRow (true, cfg, [ "S/D"; "Address"; "Name"; "Lib Name"
                               "Size"; "Type"; "Bind"; "Visibility"
                               "SectionIndex" ])
    out.PrintLine "  ---"
    elf.StaticSymbols
    |> Array.sortBy (fun s -> s.SymName)
    |> Array.sortBy (fun s -> s.Addr)
    |> Array.iter (fun s -> printSymbolInfoVerbose elf s "(s)" cfg)
    elf.DynamicSymbols
    |> Array.sortBy (fun s -> s.SymName)
    |> Array.sortBy (fun s -> s.Addr)
    |> Array.iter (fun s -> printSymbolInfoVerbose elf s "(d)" cfg)
  else
    let cfg = [ LeftAligned 3; LeftAligned 10
                addrColumn; LeftAligned 75; LeftAligned 15 ]
    out.PrintRow (true, cfg, [ "S/D"; "Kind"; "Address"; "Name"; "Lib Name" ])
    out.PrintLine "  ---"
    elf.StaticSymbols
    |> Array.sortBy (fun s -> s.SymName)
    |> Array.sortBy (fun s -> s.Addr)
    |> Array.iter (fun s -> printSymbolInfoNonVerbose elf s "(s)" cfg)
    elf.DynamicSymbols
    |> Array.sortBy (fun s -> s.SymName)
    |> Array.sortBy (fun s -> s.Addr)
    |> Array.iter (fun s -> printSymbolInfoNonVerbose elf s "(d)" cfg)

let dumpSymbols (opts: FileViewerOpts) (elf: ELFBinFile) =
  printSymbolInfo opts.Verbose elf

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
      ELF.RelocationType.ToString reloc.RelType
      reloc.RelAddend.ToString ("x")
      symbol
    ])
  )

let dumpFunctions (_: FileViewerOpts) (elf: ELFBinFile) =
  let addrColumn = columnWidthOfAddr elf |> LeftAligned
  let cfg = [ LeftAligned 3; LeftAligned 10
              addrColumn; LeftAligned 75; LeftAligned 15 ]
  for addr in (elf :> IBinFile).GetFunctionAddresses () do
    match elf.SymbolInfo.AddrToSymbTable.TryGetValue addr with
    | true, symb -> printSymbolInfoNonVerbose elf symb "" cfg
    | false, _ -> ()

let dumpExceptionTable hdl (_opts: FileViewerOpts) (file: ELFBinFile) =
  let exnInfo = ExceptionInfo (hdl=hdl)
  exnInfo.ExceptionMap
  |> NoOverlapIntervalMap.iter (fun range catchBlkAddr ->
    out.PrintLine $"{range.Min:x}:{range.Max:x} -> {catchBlkAddr:x}")

let makeStringTableReader (file: IBinFile) dynEntries =
  dynEntries
  |> Array.fold (fun (addr, len) (ent: ELF.DynamicArrayEntry) ->
    match ent.DTag with
    | ELF.DTag.DT_STRTAB -> Some ent.DVal, len
    | ELF.DTag.DT_STRSZ -> addr, Some ent.DVal
    | _ -> addr, len
  ) (None, None)
  ||> Option.map2 (fun addr len ->
    fun v ->
      let strtab = IBinFile.Slice (file, file.GetOffset addr, int len)
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
    | ELF.DTag.DT_NEEDED, Some reader ->
      out.PrintRow (true, cfg, [ $"{tag}"
                                 $"Shared library: [{reader ent.DVal}]" ])
    | ELF.DTag.DT_SONAME, Some reader ->
      out.PrintRow (true, cfg, [ $"{tag}"
                                 $"Library soname: [{reader ent.DVal}]" ])
    | ELF.DTag.DT_RPATH, Some reader ->
      out.PrintRow (true, cfg, [ $"{tag}"
                                 $"Library rpath: [{reader ent.DVal}]" ])
    | ELF.DTag.DT_RUNPATH, Some reader ->
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
          (Permission.toString (ELF.ProgramHeader.FlagsToPerm ph.PHFlags))
          ph.PHType.ToString ()
          HexString.ofUInt64 ph.PHOffset
          HexString.ofUInt64 ph.PHAddr
          HexString.ofUInt64 ph.PHPhyAddr
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
          (Permission.toString (ELF.ProgramHeader.FlagsToPerm ph.PHFlags)) ]))

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
  ELF.CanonicalFrameAddress.toString hdl.RegisterFactory cfa

let ruleToString (hdl: BinHandle) (rule: ELF.Rule) =
  rule
  |> Map.fold (fun s k v ->
    match k with
    | ELF.ReturnAddress -> s + "(ra:" + ELF.Action.toString v + ")"
    | ELF.NormalReg rid ->
      let reg = hdl.RegisterFactory.GetRegString rid
      s + "(" + reg + ":" + ELF.Action.toString v + ")") ""

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
  )

let dumpGccExceptTable _hdl (elf: ELFBinFile) =
  let addrColumn = columnWidthOfAddr elf |> LeftAligned
  let file = elf :> IBinFile
  let cfg = [ addrColumn; LeftAligned 15; LeftAligned 15; addrColumn ]
  out.PrintRow (true, cfg, [ "Address"; "LP App"; "LP Val"; "TT End" ])
  elf.ExceptionInfo.LSDAs
  |> Map.iter (fun lsdaAddr lsda ->
    let ttbase = lsda.LSDAHeader.TTBase |> Option.defaultValue 0UL
    out.PrintRow (true, cfg,
      [ Addr.toString file.ISA.WordSize lsdaAddr
        lsda.LSDAHeader.LPAppEncoding.ToString ()
        lsda.LSDAHeader.LPValueEncoding.ToString ()
        ttbase |> Addr.toString file.ISA.WordSize ])
  )

let dumpNotes _hdl (file: ELFBinFile) =
  Terminator.futureFeature ()
