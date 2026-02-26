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

module internal B2R2.RearEnd.BinScan.ELFViewer

open System
open B2R2
open B2R2.Collections
open B2R2.Logging
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.ELF
open B2R2.RearEnd.Utils

let computeMagicBytes (file: IBinFile) =
  let span = ReadOnlySpan(file.RawBytes, 0, 16)
  span.ToArray()
  |> ColoredString
  |> OutputColored

let computeEntryPoint (hdr: Header) =
  ColoredString(Green, HexString.ofUInt64 hdr.EntryPoint)
  |> OutputColored

let dumpFileHeader (_: BinScanOpts) (file: ELFBinFile) =
  let hdr = file.Header
  resetToDefaultTwoColumnConfig ()
  printor [| OutputNormal "Magic:"; computeMagicBytes file |]
  printsr [| "Class:"; "ELF" + WordSize.toString hdr.Class |]
  printsr [| "Data:"; Endian.toString hdr.Endian |]
  printsr [| "Version:"; hdr.Version.ToString() |]
  printsr [| "ABI:"; OSABI.toString hdr.OSABI |]
  printsr [| "ABI version:"; hdr.OSABIVersion.ToString() |]
  printsr [| "Type:"; ELFType.toString hdr.ELFType |]
  printsr [| "Machine:"; hdr.MachineType.ToString() |]
  printor [| OutputNormal "Entry point:"; computeEntryPoint hdr |]
  printsr [| "PHdr table offset:"; HexString.ofUInt64 hdr.PHdrTblOffset |]
  printsr [| "SHdr table offset:"; HexString.ofUInt64 hdr.SHdrTblOffset |]
  printsr [| "Flags:"; HexString.ofUInt64 (uint64 hdr.ELFFlags) |]
  printsr [| "Header size:"; toNBytes (uint64 hdr.HeaderSize) |]
  printsr [| "PHdr Entry Size:"; toNBytes (uint64 hdr.PHdrEntrySize) |]
  printsr [| "PHdr Entry Num:"; hdr.PHdrNum.ToString() |]
  printsr [| "SHdr Entry Size:"; toNBytes (uint64 (hdr.SHdrEntrySize)) |]
  printsr [| "SHdr Entry Num:"; hdr.SHdrNum.ToString() |]
  printsr [| "SHdr string index:"; hdr.SHdrStrIdx.ToString() |]
  printsn ""

let computeSectionEndAddr (s: SectionHeader) =
  if s.SecSize = 0UL then s.SecAddr
  else s.SecAddr + s.SecSize - 1UL

let makeSectionHeadersFormatVerbose addrColumn =
  [| LeftAligned 4
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
     LeftAligned 20 |]

let makeSectionHeadersTableHeaderVerbose () =
  [| "Num"
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
     "Flags" |]

let dumpSectionHeadersVerbose (elf: ELFBinFile) wordSize addrColumn =
  setTableColumnFormats <| makeSectionHeadersFormatVerbose addrColumn
  printDoubleHorizontalRule ()
  printsr <| makeSectionHeadersTableHeaderVerbose ()
  printSingleHorizontalRule ()
  for i in 0 .. elf.SectionHeaders.Length - 1 do
    let s = elf.SectionHeaders[i]
    printsr
      [| String.wrapSqrdBracket (i.ToString())
         Addr.toString wordSize s.SecAddr
         Addr.toString wordSize (computeSectionEndAddr s)
         normalizeEmpty s.SecName
         SectionType.toString s.SecType
         HexString.ofUInt64 s.SecOffset
         HexString.ofUInt64 s.SecSize
         HexString.ofUInt64 s.SecEntrySize
         s.SecLink.ToString()
         s.SecInfo.ToString()
         HexString.ofUInt64 s.SecAlignment
         normalizeEmpty (SectionFlags.toString s.SecFlags) |]
  printDoubleHorizontalRule ()
  printsn ""

let makeSectionHeadersFormatSimple addrColumn =
  [| LeftAligned 4
     addrColumn
     addrColumn
     LeftAligned 24 |]

let dumpSectionHeadersSimple (elf: ELFBinFile) wordSize addrColumn =
  setTableColumnFormats <| makeSectionHeadersFormatSimple addrColumn
  printDoubleHorizontalRule ()
  printsr [| "Num"; "Start"; "End"; "Name" |]
  printSingleHorizontalRule ()
  for i in 0 .. elf.SectionHeaders.Length - 1 do
    let s = elf.SectionHeaders[i]
    printsr
      [| String.wrapSqrdBracket (i.ToString())
         Addr.toString wordSize s.SecAddr
         Addr.toString wordSize (computeSectionEndAddr s)
         normalizeEmpty s.SecName |]
  printDoubleHorizontalRule ()
  printsn ""

let dumpSectionHeaders (opts: BinScanOpts) (elf: ELFBinFile) =
  let addrColumn = columnWidthOfAddr elf |> LeftAligned
  let wordSize = (elf :> IBinFile).ISA.WordSize
  if opts.Verbose then dumpSectionHeadersVerbose elf wordSize addrColumn
  else dumpSectionHeadersSimple elf wordSize addrColumn

let dumpSectionDetails (secname: string) (file: ELFBinFile) =
  match file.TryFindSection secname with
  | Some section ->
    resetToDefaultTwoColumnConfig ()
    printsr [| "Section number:"; section.SecNum.ToString() |]
    printsr [| "Section name:"; section.SecName |]
    printsr [| "Type:"; SectionType.toString section.SecType |]
    printsr [| "Address:"; HexString.ofUInt64 section.SecAddr |]
    printsr [| "Offset:"; HexString.ofUInt64 section.SecOffset |]
    printsr [| "Size:"; HexString.ofUInt64 section.SecSize |]
    printsr [| "Entry Size:"; HexString.ofUInt64 section.SecEntrySize |]
    printsr [| "Flag:"; section.SecFlags.ToString() |]
    printsr [| "Link:"; section.SecLink.ToString() |]
    printsr [| "Info:"; section.SecInfo.ToString() |]
    printsr [| "Alignment:"; HexString.ofUInt64 section.SecAlignment |]
    printsn ""
  | None ->
    printsn "Not found."
    printsn ""

let makeSymbolsFormatVerbose addrColumn =
  [| LeftAligned 4
     addrColumn
     LeftAligned 55
     LeftAligned 15
     LeftAligned 8
     LeftAligned 12
     LeftAligned 8
     LeftAligned 10
     LeftAligned 8 |]

let makeSymbolsTableHeaderVerbose () =
  [| "S/D"
     "Address"
     "Name"
     "Lib Name"
     "Size"
     "Type"
     "Bind"
     "Visibility"
     "SectionIndex" |]

let verInfoToString (verInfo: SymVerInfo option) =
  match verInfo with
  | Some version -> (toLibString >> normalizeEmpty) version.VerName
  | None -> ""

let getSectionSymbolName (elf: ELFBinFile) (symb: Symbol) =
  match symb.SymType, symb.SecHeaderIndex with
  | SymbolType.STT_SECTION, SectionIndex idx -> elf.SectionHeaders[idx].SecName
  | _ -> symb.SymName

let dumpSymbolVerbose elf (symb: Symbol) vis =
  printsr
  <| [| vis
        Addr.toString (elf :> IBinFile).ISA.WordSize symb.Addr
        getSectionSymbolName elf symb
        verInfoToString symb.VerInfo
        HexString.ofUInt64 symb.Size
        SymbolType.toString symb.SymType
        SymbolBind.toString symb.Bind
        SymbolVisibility.toString symb.Vis
        SectionHeaderIdx.ToString symb.SecHeaderIndex |]

let dumpSymbolsVerbose (elf: ELFBinFile) addrColumn =
  setTableColumnFormats <| makeSymbolsFormatVerbose addrColumn
  printDoubleHorizontalRule ()
  printsr <| makeSymbolsTableHeaderVerbose ()
  printSingleHorizontalRule ()
  for s in elf.Symbols.StaticSymbols do dumpSymbolVerbose elf s "(s)"
  if elf.Symbols.StaticSymbols.Length > 0 then printSingleHorizontalRule ()
  else ()
  for s in elf.Symbols.DynamicSymbols do dumpSymbolVerbose elf s "(d)"
  printDoubleHorizontalRule ()
  printsn ""

let makeSymbolsFormatSimple addrColumn =
  [| LeftAligned 3
     LeftAligned 10
     addrColumn
     LeftAligned 75
     LeftAligned 15 |]

let dumpSymbolSimple file (symb: Symbol) vis =
  printsr
  <| [| vis
        SymbolType.toString symb.SymType
        Addr.toString (file: IBinFile).ISA.WordSize symb.Addr
        normalizeEmpty symb.SymName
        normalizeEmpty (verInfoToString symb.VerInfo) |]

let dumpSymbolsSimple (elf: ELFBinFile) addrColumn =
  setTableColumnFormats <| makeSymbolsFormatSimple addrColumn
  printDoubleHorizontalRule ()
  printsr [| "S/D"; "Kind"; "Address"; "Name"; "Lib Name" |]
  printSingleHorizontalRule ()
  for s in elf.Symbols.StaticSymbols do dumpSymbolSimple elf s "(s)"
  if elf.Symbols.StaticSymbols.Length > 0 then printSingleHorizontalRule ()
  else ()
  for s in elf.Symbols.DynamicSymbols do dumpSymbolSimple elf s "(d)"
  printDoubleHorizontalRule ()
  printsn ""

let dumpSymbols (opts: BinScanOpts) elf =
  let addrColumn = columnWidthOfAddr elf |> LeftAligned
  if opts.Verbose then dumpSymbolsVerbose elf addrColumn
  else dumpSymbolsSimple elf addrColumn

let getRelocSymbolName reloc =
  match reloc.RelSymbol with
  | Some s -> normalizeEmpty s.SymName
  | None -> "(n/a)"

let dumpRelocs _ (elf: ELFBinFile) =
  let addrColumn = columnWidthOfAddr elf |> LeftAligned
  let colfmts = [| addrColumn; LeftAligned 24; RightAligned 8; LeftAligned 12 |]
  let wordSize = (elf :> IBinFile).ISA.WordSize
  let sortedRelocs =
    elf.RelocationInfo.Entries |> Seq.sortBy (fun reloc -> reloc.RelOffset)
  setTableColumnFormats colfmts
  printDoubleHorizontalRule ()
  printsr [| "Address"; "Type"; "Addended"; "Symbol" |]
  printSingleHorizontalRule ()
  for reloc in sortedRelocs do
    printsr [| Addr.toString wordSize reloc.RelOffset
               RelocationKind.ToString reloc.RelKind
               reloc.RelAddend.ToString("x")
               getRelocSymbolName reloc |]
  printDoubleHorizontalRule ()
  printsn ""

let makeFunctionsFormat elf =
  let addrColumn = columnWidthOfAddr elf |> LeftAligned
  [| addrColumn
     LeftAligned 75 |]

let dumpFunctions _ (elf: ELFBinFile) =
  setTableColumnFormats <| makeFunctionsFormat elf
  printDoubleHorizontalRule ()
  printsr [| "Address"; "Name" |]
  printSingleHorizontalRule ()
  for addr in (elf :> IBinFile).GetFunctionAddresses() do
    match elf.Symbols.TryFindSymbol addr with
    | Ok symb ->
      printsr
      <| [| Addr.toString (elf: IBinFile).ISA.WordSize symb.Addr
            normalizeEmpty symb.SymName |]
    | Error _ -> ()
  printDoubleHorizontalRule ()
  printsn ""

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
  let dynEntries = file.DynamicArrayEntries
  let strtabReader = makeStringTableReader file dynEntries
  setTableColumnFormats [| LeftAligned 20; LeftAligned 20 |]
  printDoubleHorizontalRule ()
  printsr [| "Tag"; "Name/Value" |]
  printSingleHorizontalRule ()
  for { DTag = tag; DVal = v } in dynEntries do
    match tag, strtabReader with
    | DTag.DT_NEEDED, Some reader ->
      printsr [| $"{tag}"; $"Shared library: [{reader v}]" |]
    | DTag.DT_SONAME, Some reader ->
      printsr [| $"{tag}"; $"Library soname: [{reader v}]" |]
    | DTag.DT_RPATH, Some reader ->
      printsr [| $"{tag}"; $"Library rpath: [{reader v}]" |]
    | DTag.DT_RUNPATH, Some reader ->
      printsr [| $"{tag}"; $"Library runpath: [{reader v}]" |]
    | _ ->
      printsr [| $"{tag}"; "0x" + v.ToString "x" |]
  printDoubleHorizontalRule ()
  printsn ""

let makeSegmentsFormatVerbose addrColumn =
  [| LeftAligned 4
     addrColumn
     addrColumn
     LeftAligned 10
     LeftAligned 12
     LeftAligned 8
     addrColumn
     addrColumn
     LeftAligned 8
     LeftAligned 8
     LeftAligned 8 |]

let makeSegmentsTableHeaderVerbose () =
  [| "Num"
     "Start"
     "End"
     "Permission"
     "Type"
     "Offset"
     "VirtAddr"
     "PhysAddr"
     "FileSize"
     "MemSize"
     "Alignment" |]

let dumpSegmentsVerbose (elf: ELFBinFile) wordSize addrColumn =
  setTableColumnFormats <| makeSegmentsFormatVerbose addrColumn
  printDoubleHorizontalRule ()
  printsr <| makeSegmentsTableHeaderVerbose ()
  printSingleHorizontalRule ()
  for i in 0 .. elf.ProgramHeaders.Length - 1 do
    let p = elf.ProgramHeaders[i]
    printsr [| String.wrapSqrdBracket (i.ToString())
               Addr.toString wordSize p.PHAddr
               Addr.toString wordSize (p.PHAddr + p.PHMemSize - uint64 1)
               Permission.toString (ProgramHeader.FlagsToPerm p.PHFlags)
               ProgramHeaderType.toString p.PHType
               HexString.ofUInt64 p.PHOffset
               Addr.toString wordSize p.PHAddr
               Addr.toString wordSize p.PHPhyAddr
               HexString.ofUInt64 p.PHFileSize
               HexString.ofUInt64 p.PHMemSize
               HexString.ofUInt64 p.PHAlignment |]
  printDoubleHorizontalRule ()
  printsn ""

let dumpSegmentsSimple (elf: ELFBinFile) wordSize addrColumn =
  let colfmts = [| LeftAligned 4; addrColumn; addrColumn; LeftAligned 10 |]
  setTableColumnFormats colfmts
  printDoubleHorizontalRule ()
  printsr [| "Num"; "Start"; "End"; "Permission" |]
  printSingleHorizontalRule ()
  for i in 0 .. elf.ProgramHeaders.Length - 1 do
    let p = elf.ProgramHeaders[i]
    printsr [| String.wrapSqrdBracket (i.ToString())
               Addr.toString wordSize p.PHAddr
               Addr.toString wordSize (p.PHAddr + p.PHMemSize - 1UL)
               Permission.toString (ProgramHeader.FlagsToPerm p.PHFlags) |]
  printDoubleHorizontalRule ()
  printsn ""

let dumpSegments (opts: BinScanOpts) (elf: ELFBinFile) =
  let addrColumn = columnWidthOfAddr elf |> LeftAligned
  let wordSize = (elf :> IBinFile).ISA.WordSize
  if opts.Verbose then dumpSegmentsVerbose elf wordSize addrColumn
  else dumpSegmentsSimple elf wordSize addrColumn

let makeLinkageTableFormatVerbose addrColumn =
  [| addrColumn
     addrColumn
     LeftAligned 40
     LeftAligned 15
     LeftAligned 8
     LeftAligned 6
     LeftAligned 4 |]

let makeLinkageTableHeaderVerbose () =
  [| "PLT Addr"
     "GOT Addr"
     "FunctionName"
     "Lib Name"
     "Addend"
     "SecIdx"
     "Type" |]

let dumpLinkageTableVerbose (elf: ELFBinFile) wordSize addrColumn =
  setTableColumnFormats <| makeLinkageTableFormatVerbose addrColumn
  printDoubleHorizontalRule ()
  printsr <| makeLinkageTableHeaderVerbose ()
  printSingleHorizontalRule ()
  for e in (elf :> IBinFile).GetLinkageTableEntries() do
    match elf.RelocationInfo.TryFind e.TableAddress with
    | Ok reloc ->
      printsr [| Addr.toString wordSize e.TrampolineAddress
                 Addr.toString wordSize e.TableAddress
                 normalizeEmpty e.FuncName
                 (toLibString >> normalizeEmpty) e.LibraryName
                 reloc.RelAddend.ToString()
                 reloc.RelSecNumber.ToString()
                 RelocationKind.ToString reloc.RelKind |]
    | _ ->
      printsr [| Addr.toString wordSize e.TrampolineAddress
                 Addr.toString wordSize e.TableAddress
                 normalizeEmpty e.FuncName
                 (toLibString >> normalizeEmpty) e.LibraryName
                 "(n/a)"
                 "(n/a)"
                 "(n/a)" |]
  printDoubleHorizontalRule ()
  printsn ""

let dumpLinkageTableSimple (elf: ELFBinFile) wordSize addrColumn =
  let colfmts = [| addrColumn; addrColumn; LeftAligned 20; LeftAligned 15 |]
  setTableColumnFormats colfmts
  printDoubleHorizontalRule ()
  printsr [| "PLT"; "GOT"; "FunctionName"; "Lib Name" |]
  printSingleHorizontalRule ()
  for e in (elf :> IBinFile).GetLinkageTableEntries() do
    printsr [| Addr.toString wordSize e.TrampolineAddress
               Addr.toString wordSize e.TableAddress
               normalizeEmpty e.FuncName
               (toLibString >> normalizeEmpty) e.LibraryName |]
  printDoubleHorizontalRule ()
  printsn ""

let dumpLinkageTable (opts: BinScanOpts) (elf: ELFBinFile) =
  let addrColumn = columnWidthOfAddr elf |> LeftAligned
  let wordSize = (elf :> IBinFile).ISA.WordSize
  if opts.Verbose then dumpLinkageTableVerbose elf wordSize addrColumn
  else dumpLinkageTableSimple elf wordSize addrColumn

let dumpExceptionTable hdl (elf: ELFBinFile) =
  let addrColumn = columnWidthOfAddr elf |> LeftAligned
  let exnInfo = ExceptionInfo(hdl = hdl)
  setTableColumnFormats [| addrColumn; addrColumn; addrColumn |]
  printDoubleHorizontalRule ()
  printsr [| "RangeStart"; "RangeEnd"; "CatchBlk" |]
  printSingleHorizontalRule ()
  if NoOverlapIntervalMap.isEmpty exnInfo.ExceptionMap then
    printsn "n/a"
  else
    exnInfo.ExceptionMap
    |> NoOverlapIntervalMap.iter (fun range catchBlkAddr ->
      printsr [| $"{range.Min:x}"; $"{range.Max:x}"; $"{catchBlkAddr:x}" |])
  printDoubleHorizontalRule ()
  printsn ""

let cfaToString (hdl: BinHandle) cfa =
  CanonicalFrameAddress.ToString(hdl.RegisterFactory, cfa)

let ruleToString (hdl: BinHandle) (rule: UnwindingRule) =
  if Map.isEmpty rule then
    normalizeEmpty ""
  else
    rule
    |> Map.fold (fun s k v ->
      match k with
      | ReturnAddress -> s + "(ra:" + UnwindingAction.ToString v + ")"
      | NormalReg rid ->
        let reg = hdl.RegisterFactory.GetRegisterName rid
        s + "(" + reg + ":" + UnwindingAction.ToString v + ")") ""

let dumpUnwindingInfo hdl fde =
  if fde.UnwindingInfo.IsEmpty then
    printsn <| normalizeEmpty ""
  else
    printDoubleHorizontalRule ()
    printsr [| "Location"; "CFA"; "Rules" |]
    printSingleHorizontalRule ()
    for info in fde.UnwindingInfo do
      printsr [| HexString.ofUInt64 info.Location
                 cfaToString hdl info.CanonicalFrameAddress
                 ruleToString hdl info.Rule |]
    printDoubleHorizontalRule ()
  printsn ""

let dumpEHFrame hdl (file: ELFBinFile) =
  let addrColumn = columnWidthOfAddr file |> LeftAligned
  let colfmts = [| addrColumn; LeftAligned 10; LeftAligned 50 |]
  setTableColumnFormats colfmts
  for cfi in file.ExceptionFrame do
    let aug = cfi.CIE.AugmentationString
    let cf = cfi.CIE.CodeAlignmentFactor.ToString("+0;-#")
    let df = cfi.CIE.DataAlignmentFactor.ToString("+0;-#")
    printSubsectionTitle $"CIE: {aug} cf={cf} df={df}"
    for fde in cfi.FDEs do
      let pcBegin = HexString.ofUInt64 fde.PCBegin
      let pcEnd = HexString.ofUInt64 fde.PCEnd
      printSubsubsectionTitle $"FDE pc={pcBegin}..{pcEnd}"
      dumpUnwindingInfo hdl fde
  printsn ""

let dumpGccExceptTable _hdl (elf: ELFBinFile) =
  let addrColumn = columnWidthOfAddr elf |> LeftAligned
  let file = elf :> IBinFile
  let colfmts = [| addrColumn; LeftAligned 15; LeftAligned 15; addrColumn |]
  setTableColumnFormats colfmts
  printDoubleHorizontalRule ()
  printsr [| "Address"; "LP App"; "LP Val"; "TT End" |]
  printSingleHorizontalRule ()
  elf.LSDATable
  |> Map.iter (fun lsdaAddr lsda ->
    let ttbase = lsda.TTBase |> Option.defaultValue 0UL
    printsr [| Addr.toString file.ISA.WordSize lsdaAddr
               lsda.LPAppEncoding.ToString()
               lsda.LPValueEncoding.ToString()
               ttbase |> Addr.toString file.ISA.WordSize |])
  printDoubleHorizontalRule ()
  printsn ""

let dumpNotes _hdl (_file: ELFBinFile) =
  Terminator.futureFeature ()
