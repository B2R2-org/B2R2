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
open B2R2.Logging
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.ELF
open B2R2.RearEnd.FileViewer.Helper

let badAccess _ _ = raise InvalidFileFormatException

let computeMagicBytes (file: IBinFile) =
  let span = System.ReadOnlySpan(file.RawBytes, 0, 16)
  span.ToArray()
  |> ColoredString
  |> OutputColored

let computeEntryPoint (hdr: Header) =
  ColoredString(Green, HexString.ofUInt64 hdr.EntryPoint)
  |> OutputColored

let dumpFileHeader (_: FileViewerOpts) (file: ELFBinFile) =
  let hdr = file.Header
  Log.Out
  <== TableConfig.DefaultTwoColumn
  <== [ OutputNormal "Magic:"; computeMagicBytes file ]
  <== [ "Class:"; "ELF" + WordSize.toString hdr.Class ]
  <== [ "Data:"; Endian.toString hdr.Endian ]
  <== [ "Version:"; hdr.Version.ToString() ]
  <== [ "ABI:"; OSABI.toString hdr.OSABI ]
  <== [ "ABI version:"; hdr.OSABIVersion.ToString() ]
  <== [ "Type:"; ELFType.toString hdr.ELFType ]
  <== [ "Machine:"; hdr.MachineType.ToString() ]
  <== [ OutputNormal "Entry point:"; computeEntryPoint hdr ]
  <== [ "PHdr table offset:"; HexString.ofUInt64 hdr.PHdrTblOffset ]
  <== [ "SHdr table offset:"; HexString.ofUInt64 hdr.SHdrTblOffset ]
  <== [ "Flags:"; HexString.ofUInt64 (uint64 hdr.ELFFlags) ]
  <== [ "Header size:"; toNBytes (uint64 hdr.HeaderSize) ]
  <== [ "PHdr Entry Size:"; toNBytes (uint64 hdr.PHdrEntrySize) ]
  <== [ "PHdr Entry Num:"; hdr.PHdrNum.ToString() ]
  <== [ "SHdr Entry Size:"; toNBytes (uint64 (hdr.SHdrEntrySize)) ]
  <== [ "SHdr Entry Num:"; hdr.SHdrNum.ToString() ]
  <=/ [ "SHdr string index:"; hdr.SHdrStrIdx.ToString() ]

let computeSectionEndAddr (s: SectionHeader) =
  if s.SecSize = 0UL then s.SecAddr
  else s.SecAddr + s.SecSize - 1UL

let dumpSectionHeaders (opts: FileViewerOpts) (elf: ELFBinFile) =
  let addrColumn = columnWidthOfAddr elf |> LeftAligned
  let file = elf :> IBinFile
  if opts.Verbose then
    let cfg =
      { TableConfig.DefaultTwoColumn with
          Indentation = 2
          Columns = [ LeftAligned 4
                      addrColumn
                      addrColumn
                      LeftAligned 24
                      LeftAligned 14
                      LeftAligned 12
                      LeftAligned 8
                      LeftAligned 10
                      LeftAligned 4
                      LeftAligned 4
                      LeftAligned 6
                      LeftAligned 20 ] }
    Log.Out
    <== cfg
    <== [ "Num"
          "Start"
          "End"
          "Name"
          "Type"
          "Offset"
          "Size"
          "EntrySize"
          "Link"
          "Info"
          "Align"
          "Flags" ]
    <=/ "  ---"
    elf.SectionHeaders
    |> Array.iteri (fun idx s ->
      Log.Out <=/
        [ String.wrapSqrdBracket (idx.ToString())
          Addr.toString file.ISA.WordSize s.SecAddr
          Addr.toString file.ISA.WordSize (computeSectionEndAddr s)
          normalizeEmpty s.SecName
          SectionType.toString s.SecType
          HexString.ofUInt64 s.SecOffset
          HexString.ofUInt64 s.SecSize
          HexString.ofUInt64 s.SecEntrySize
          s.SecLink.ToString()
          s.SecInfo.ToString()
          HexString.ofUInt64 s.SecAlignment
          normalizeEmpty (SectionFlags.toString s.SecFlags) ]
    )
  else
    let cfg =
      { TableConfig.DefaultTwoColumn with
          Indentation = 2
          Columns = [ LeftAligned 4; addrColumn; addrColumn; LeftAligned 24 ] }
    Log.Out
    <== cfg
    <== [ "Num"; "Start"; "End"; "Name" ]
    <=/ "  ---"
    elf.SectionHeaders
    |> Seq.iteri (fun idx s ->
      Log.Out <=/
        [ String.wrapSqrdBracket (idx.ToString())
          Addr.toString file.ISA.WordSize s.SecAddr
          Addr.toString file.ISA.WordSize (computeSectionEndAddr s)
          normalizeEmpty s.SecName ]
    )

let dumpSectionDetails (secname: string) (file: ELFBinFile) =
  match file.TryFindSection secname with
  | Some section ->
    Log.Out
    <== TableConfig.DefaultTwoColumn
    <== [ "Section number:"; section.SecNum.ToString() ]
    <== [ "Section name:"; section.SecName ]
    <== [ "Type:"; SectionType.toString section.SecType ]
    <== [ "Address:"; HexString.ofUInt64 section.SecAddr ]
    <== [ "Offset:"; HexString.ofUInt64 section.SecOffset ]
    <== [ "Size:"; HexString.ofUInt64 section.SecSize ]
    <== [ "Entry Size:"; HexString.ofUInt64 section.SecEntrySize ]
    <== [ "Flag:"; section.SecFlags.ToString() ]
    <== [ "Link:"; section.SecLink.ToString() ]
    <== [ "Info:"; section.SecInfo.ToString() ]
    <=/ [ "Alignment:"; HexString.ofUInt64 section.SecAlignment ]
  | None -> Log.Out <=/ "Not found."

let verInfoToString (verInfo: SymVerInfo option) =
  match verInfo with
  | Some version -> (toLibString >> normalizeEmpty) version.VerName
  | None -> ""

let getSectionSymbolName (elf: ELFBinFile) (symb: Symbol) =
  match symb.SymType, symb.SecHeaderIndex with
  | SymbolType.STT_SECTION, SectionIndex idx -> elf.SectionHeaders[idx].SecName
  | _ -> symb.SymName

let printSymbolInfoVerbose elf (symb: Symbol) vis (cfg: TableConfig) =
  Log.Out
  <== cfg
  <=/ [ vis
        Addr.toString (elf :> IBinFile).ISA.WordSize symb.Addr
        getSectionSymbolName elf symb
        verInfoToString symb.VerInfo
        HexString.ofUInt64 symb.Size
        SymbolType.toString symb.SymType
        SymbolBind.toString symb.Bind
        SymbolVisibility.toString symb.Vis
        SectionHeaderIdx.ToString symb.SecHeaderIndex ]

let printSymbolInfoNonVerbose file (symb: Symbol) vis (cfg: TableConfig) =
  Log.Out
  <== cfg
  <=/ [ vis
        SymbolType.toString symb.SymType
        Addr.toString (file: IBinFile).ISA.WordSize symb.Addr
        normalizeEmpty symb.SymName
        normalizeEmpty (verInfoToString symb.VerInfo) ]

let printSymbolInfo isVerbose (elf: ELFBinFile) =
  let addrColumn = columnWidthOfAddr elf |> LeftAligned
  if isVerbose then
    let cfg =
      { TableConfig.DefaultTwoColumn with
          Indentation = 2
          Columns = [ LeftAligned 4
                      addrColumn
                      LeftAligned 55
                      LeftAligned 15
                      LeftAligned 8
                      LeftAligned 12
                      LeftAligned 8
                      LeftAligned 10
                      LeftAligned 8 ] }
    Log.Out
    <== cfg
    <== [ "S/D"
          "Address"
          "Name"
          "Lib Name"
          "Size"
          "Type"
          "Bind"
          "Visibility"
          "SectionIndex" ]
    <=/ "  ---"
    elf.Symbols.StaticSymbols
    |> Array.iter (fun s -> printSymbolInfoVerbose elf s "(s)" cfg)
    Log.Out <=/ "  ---"
    elf.Symbols.DynamicSymbols
    |> Array.iter (fun s -> printSymbolInfoVerbose elf s "(d)" cfg)
  else
    let cfg =
      { TableConfig.DefaultTwoColumn with
          Indentation = 2
          Columns = [ LeftAligned 3
                      LeftAligned 10
                      addrColumn
                      LeftAligned 75
                      LeftAligned 15 ] }
    Log.Out
    <== cfg
    <== [ "S/D"; "Kind"; "Address"; "Name"; "Lib Name" ]
    <=/ "  ---"
    elf.Symbols.StaticSymbols
    |> Array.iter (fun s -> printSymbolInfoNonVerbose elf s "(s)" cfg)
    Log.Out <=/ "  ---"
    elf.Symbols.DynamicSymbols
    |> Array.iter (fun s -> printSymbolInfoNonVerbose elf s "(d)" cfg)

let dumpSymbols (opts: FileViewerOpts) (elf: ELFBinFile) =
  printSymbolInfo opts.Verbose elf

let dumpRelocs (_opts: FileViewerOpts) (elf: ELFBinFile) =
  let addrColumn = columnWidthOfAddr elf |> LeftAligned
  let colfmts = [ addrColumn; LeftAligned 24; RightAligned 8; LeftAligned 12 ]
  Log.Out
  <== colfmts
  <== [ "Address"; "Type"; "Addended"; "Symbol" ]
  <=/ "  ---"
  elf.RelocationInfo.Entries
  |> Seq.sortBy (fun reloc -> reloc.RelOffset)
  |> Seq.iter (fun reloc ->
    let symbol =
      match reloc.RelSymbol with
      | Some s when s.SymName.Length > 0 -> s.SymName
      | _ -> "(n/a)"
    Log.Out
    <=/ [ Addr.toString (elf :> IBinFile).ISA.WordSize reloc.RelOffset
          RelocationKind.ToString reloc.RelKind
          reloc.RelAddend.ToString("x")
          symbol ]
  )

let dumpFunctions (_: FileViewerOpts) (elf: ELFBinFile) =
  let addrColumn = columnWidthOfAddr elf |> LeftAligned
  let cfg =
    { TableConfig.DefaultTwoColumn with
        Indentation = 2
        Columns = [ LeftAligned 3
                    LeftAligned 10
                    addrColumn
                    LeftAligned 75
                    LeftAligned 15 ] }
  for addr in (elf :> IBinFile).GetFunctionAddresses() do
    match elf.Symbols.TryFindSymbol addr with
    | Ok symb -> printSymbolInfoNonVerbose elf symb "" cfg
    | Error _ -> ()

let dumpExceptionTable hdl (_opts: FileViewerOpts) (_file: ELFBinFile) =
  let exnInfo = ExceptionInfo(hdl = hdl)
  exnInfo.ExceptionMap
  |> NoOverlapIntervalMap.iter (fun range catchBlkAddr ->
    Log.Out <=/ $"{range.Min:x}:{range.Max:x} -> {catchBlkAddr:x}")

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
      let strtab = file.Slice(addr, int len)
      let buf = strtab.Slice(int v)
      ByteArray.extractCStringFromSpan buf 0)

let dumpDynamicSection _ (file: ELFBinFile) =
  Log.Out
  <== [ LeftAligned 20; LeftAligned 20 ]
  <== [ "Tag"; "Name/Value" ]
  <=/ "  ---"
  let dynEntries = file.DynamicArrayEntries
  let strtabReader = makeStringTableReader file dynEntries
  dynEntries
  |> Array.iter (fun ent ->
    let tag = ent.DTag
    match tag, strtabReader with
    | DTag.DT_NEEDED, Some reader ->
      Log.Out <=/ [ $"{tag}"; $"Shared library: [{reader ent.DVal}]" ]
    | DTag.DT_SONAME, Some reader ->
      Log.Out <=/ [ $"{tag}"; $"Library soname: [{reader ent.DVal}]" ]
    | DTag.DT_RPATH, Some reader ->
      Log.Out <=/ [ $"{tag}"; $"Library rpath: [{reader ent.DVal}]" ]
    | DTag.DT_RUNPATH, Some reader ->
      Log.Out <=/ [ $"{tag}"; $"Library runpath: [{reader ent.DVal}]" ]
    | _ ->
      Log.Out <=/ [ $"{tag}"; "0x" + ent.DVal.ToString "x" ]
  )

let dumpSegments (opts: FileViewerOpts) (elf: ELFBinFile) =
  let addrColumn = columnWidthOfAddr elf |> LeftAligned
  let file = elf :> IBinFile
  if opts.Verbose then
    Log.Out
    <== [ LeftAligned 4
          addrColumn
          addrColumn
          LeftAligned 10
          LeftAligned 12
          LeftAligned 8
          addrColumn
          addrColumn
          LeftAligned 8
          LeftAligned 8
          LeftAligned 8 ]
    <== [ "Num"
          "Start"
          "End"
          "Permission"
          "Type"
          "Offset"
          "VirtAddr"
          "PhysAddr"
          "FileSize"
          "MemSize"
          "Alignment" ]
    <=/ "  ---"
    let wordSize = file.ISA.WordSize
    elf.ProgramHeaders
    |> Array.iteri (fun idx ph ->
      Log.Out
      <=/ [ String.wrapSqrdBracket (idx.ToString())
            Addr.toString wordSize ph.PHAddr
            Addr.toString wordSize (ph.PHAddr + ph.PHMemSize - uint64 1)
            Permission.toString (ProgramHeader.FlagsToPerm ph.PHFlags)
            ProgramHeaderType.toString ph.PHType
            HexString.ofUInt64 ph.PHOffset
            Addr.toString wordSize ph.PHAddr
            Addr.toString wordSize ph.PHPhyAddr
            HexString.ofUInt64 ph.PHFileSize
            HexString.ofUInt64 ph.PHMemSize
            HexString.ofUInt64 ph.PHAlignment ]
    )
  else
    Log.Out
    <== [ LeftAligned 4; addrColumn; addrColumn; LeftAligned 10 ]
    <== [ "Num"; "Start"; "End"; "Permission" ]
    <=/ "  ---"
    elf.ProgramHeaders
    |> Array.iteri (fun idx ph ->
      Log.Out
      <=/ [ String.wrapSqrdBracket (idx.ToString())
            Addr.toString file.ISA.WordSize ph.PHAddr
            Addr.toString file.ISA.WordSize (ph.PHAddr + ph.PHMemSize - 1UL)
            Permission.toString (ProgramHeader.FlagsToPerm ph.PHFlags) ]
    )

let dumpLinkageTable (opts: FileViewerOpts) (elf: ELFBinFile) =
  let addrColumn = columnWidthOfAddr elf |> LeftAligned
  let file = elf :> IBinFile
  if opts.Verbose then
    Log.Out
    <== [ addrColumn
          addrColumn
          LeftAligned 40
          LeftAligned 15
          LeftAligned 8
          LeftAligned 6
          LeftAligned 4 ]
    <== [ "PLT Addr"
          "GOT Addr"
          "FunctionName"
          "Lib Name"
          "Addend"
          "SecIdx"
          "Type" ]
    <=/ "  ---"
    file.GetLinkageTableEntries()
    |> Seq.iter (fun e ->
      match elf.RelocationInfo.TryFind e.TableAddress with
      | Ok reloc ->
        Log.Out
        <=/ [ Addr.toString file.ISA.WordSize e.TrampolineAddress
              Addr.toString file.ISA.WordSize e.TableAddress
              normalizeEmpty e.FuncName
              (toLibString >> normalizeEmpty) e.LibraryName
              reloc.RelAddend.ToString()
              reloc.RelSecNumber.ToString()
              RelocationKind.ToString reloc.RelKind ]
      | _ ->
        Log.Out
        <=/ [ Addr.toString file.ISA.WordSize e.TrampolineAddress
              Addr.toString file.ISA.WordSize e.TableAddress
              normalizeEmpty e.FuncName
              (toLibString >> normalizeEmpty) e.LibraryName
              "(n/a)"
              "(n/a)"
              "(n/a)" ]
    )
  else
    Log.Out
    <== [ addrColumn; addrColumn; LeftAligned 20; LeftAligned 15 ]
    <== [ "PLT"; "GOT"; "FunctionName"; "Lib Name" ]
    <=/ "  ---"
    file.GetLinkageTableEntries()
    |> Seq.iter (fun e ->
      Log.Out
      <=/ [ Addr.toString file.ISA.WordSize e.TrampolineAddress
            Addr.toString file.ISA.WordSize e.TableAddress
            normalizeEmpty e.FuncName
            (toLibString >> normalizeEmpty) e.LibraryName ]
    )

let cfaToString (hdl: BinHandle) cfa =
  CanonicalFrameAddress.ToString(hdl.RegisterFactory, cfa)

let ruleToString (hdl: BinHandle) (rule: UnwindingRule) =
  rule
  |> Map.fold (fun s k v ->
    match k with
    | ReturnAddress -> s + "(ra:" + UnwindingAction.ToString v + ")"
    | NormalReg rid ->
      let reg = hdl.RegisterFactory.GetRegisterName rid
      s + "(" + reg + ":" + UnwindingAction.ToString v + ")") ""

let dumpEHFrame hdl (file: ELFBinFile) =
  let addrColumn = columnWidthOfAddr file |> LeftAligned
  Log.Out <=/ [ addrColumn; LeftAligned 10; LeftAligned 50 ]
  file.ExceptionFrame
  |> List.iter (fun cfi ->
    Log.Out.PrintLine("- CIE: \"{0}\" cf={1} df={2}",
      cfi.CIE.AugmentationString,
      cfi.CIE.CodeAlignmentFactor.ToString("+0;-#"),
      cfi.CIE.DataAlignmentFactor.ToString("+0;-#")
    )
    Log.Out.PrintLine()
    for fde in cfi.FDEs do
      Log.Out.PrintLine("  FDE pc={0}..{1}",
        HexString.ofUInt64 fde.PCBegin,
        HexString.ofUInt64 fde.PCEnd
      )
      if fde.UnwindingInfo.IsEmpty then ()
      else
        Log.Out.PrintLine "  ---"
        Log.Out <=/ [ "Location"; "CFA"; "Rules" ]
      fde.UnwindingInfo
      |> List.iter (fun i ->
        Log.Out
        <=/ [ HexString.ofUInt64 i.Location
              cfaToString hdl i.CanonicalFrameAddress
              ruleToString hdl i.Rule ]
      )
      Log.Out.PrintLine()
  )

let dumpGccExceptTable _hdl (elf: ELFBinFile) =
  let addrColumn = columnWidthOfAddr elf |> LeftAligned
  let file = elf :> IBinFile
  Log.Out
  <== [ addrColumn; LeftAligned 15; LeftAligned 15; addrColumn ]
  <=/ [ "Address"; "LP App"; "LP Val"; "TT End" ]
  elf.LSDATable
  |> Map.iter (fun lsdaAddr lsda ->
    let ttbase = lsda.TTBase |> Option.defaultValue 0UL
    Log.Out
    <=/ [ Addr.toString file.ISA.WordSize lsdaAddr
          lsda.LPAppEncoding.ToString()
          lsda.LPValueEncoding.ToString()
          ttbase |> Addr.toString file.ISA.WordSize ]
  )

let dumpNotes _hdl (_file: ELFBinFile) = Terminator.futureFeature ()
