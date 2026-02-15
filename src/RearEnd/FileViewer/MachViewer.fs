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

module internal B2R2.RearEnd.FileViewer.MachViewer

open System
open B2R2
open B2R2.Logging
open B2R2.FrontEnd.BinFile
open B2R2.RearEnd.Utils

let magicToString (hdr: Mach.Header) =
  let magic = hdr.Magic
  HexString.ofUInt64 (uint64 magic) + String.wrapParen (magic.ToString())

let dumpFileHeader _ (file: MachBinFile) =
  let hdr = file.Header
  resetToDefaultTwoColumnConfig ()
  printsr [| "Magic:"; magicToString hdr |]
  printsr [| "CPU type:"; hdr.CPUType.ToString() |]
  printsr [| "CPU subtype:"; HexString.ofInt32 (int hdr.CPUSubType) |]
  printsr [| "File type:"; hdr.FileType.ToString() |]
  printsr [| "Number of commands:"; hdr.NumCmds.ToString() |]
  printsr [| "Size of commands:"; hdr.SizeOfCmds.ToString() |]
  printsr [| "Flags:"; HexString.ofUInt64 (uint64 hdr.Flags) |]
  for flag in enumerateFlags hdr.Flags do
    printsr [| ""; String.ofEnum flag |]
  printsn ""

let makeSectionHeadersFormatVerbose addrColumn =
  [| LeftAligned 4
     addrColumn
     addrColumn
     LeftAligned 16
     LeftAligned 8
     LeftAligned 8
     LeftAligned 8
     LeftAligned 8
     LeftAligned 10
     LeftAligned 8
     LeftAligned 22
     LeftAligned 4
     LeftAligned 4
     LeftAligned 8 |]

let makeSectionHeadersTableHeaderVerbose () =
  [| "Num"
     "Start"
     "End"
     "Name"
     "SegName"
     "Size"
     "Offset"
     "Align"
     "SecRelOff"
     "NumReloc"
     "Type"
     "Res1"
     "Res2"
     "Attrib" |]

let dumpSectionHeadersVerbose (mach: MachBinFile) wordSize addrColumn =
  setTableColumnFormats <| makeSectionHeadersFormatVerbose addrColumn
  printDoubleHorizontalRule ()
  printsr <| makeSectionHeadersTableHeaderVerbose ()
  printSingleHorizontalRule ()
  for i in 0 .. mach.Sections.Length - 1 do
    let s = mach.Sections[i]
    printsr [| String.wrapSqrdBracket (i.ToString())
               Addr.toString wordSize s.SecAddr
               Addr.toString wordSize (s.SecAddr + s.SecSize - uint64 1)
               normalizeEmpty s.SecName
               normalizeEmpty s.SegName
               HexString.ofUInt64 s.SecSize
               HexString.ofUInt64 (uint64 s.SecOffset)
               HexString.ofUInt64 (uint64 s.SecAlignment)
               s.SecRelOff.ToString()
               s.SecNumOfReloc.ToString()
               s.SecType.ToString()
               s.SecReserved1.ToString()
               s.SecReserved2.ToString()
               HexString.ofUInt32 (uint32 s.SecAttrib) |]
    for attr in enumerateFlags s.SecAttrib do
      let attr = String.ofEnum attr
      printsr [| ""; ""; ""; ""; ""; ""; ""; ""; ""; ""; ""; ""; ""; attr |]
  printDoubleHorizontalRule ()
  printsn ""

let dumpSectionHeadersSimple (mach: MachBinFile) wordSize addrColumn =
  setTableColumnFormats
    [| LeftAligned 4; addrColumn; addrColumn; LeftAligned 24 |]
  printDoubleHorizontalRule ()
  printsr [| "Num"; "Start"; "End"; "Name" |]
  printSingleHorizontalRule ()
  for i in 0 .. mach.Sections.Length - 1 do
    let s = mach.Sections[i]
    printsr [| String.wrapSqrdBracket (i.ToString())
               Addr.toString wordSize s.SecAddr
               Addr.toString wordSize (s.SecAddr + uint64 s.SecSize - 1UL)
               normalizeEmpty s.SecName |]
  printDoubleHorizontalRule ()
  printsn ""

let dumpSectionHeaders (opts: FileViewerOpts) (mach: MachBinFile) =
  let addrColumn = columnWidthOfAddr mach |> LeftAligned
  let wordSize = (mach :> IBinFile).ISA.WordSize
  if opts.Verbose then dumpSectionHeadersVerbose mach wordSize addrColumn
  else dumpSectionHeadersSimple mach wordSize addrColumn

let toVersionString (v: uint32) =
  let major = (v &&& uint32 0xFFFF0000) >>> 16
  let minor1 = (v &&& uint32 0x0000FF00) >>> 8
  let minor2 = v &&& uint32 0x000000FF
  major.ToString() + "." + minor1.ToString() + "." + minor2.ToString()

let getSymbolLibName (symbol: Mach.Symbol) =
  match symbol.VerInfo with
  | Some v -> toLibString v.DyLibName |> normalizeEmpty
  | None -> normalizeEmpty ""

let getLibName (symb: Mach.Symbol) =
  match symb.VerInfo with
  | Some info ->
    let cmpVer = toVersionString info.DyLibCmpVer
    let curVer = toVersionString info.DyLibCurVer
    let verString = $"compatibility version {cmpVer}, current version {curVer}"
    info.DyLibName + " " + String.wrapParen verString
  | None ->
    normalizeEmpty ""

let dumpSymbolVerbose wordSize vis (symb: Mach.Symbol) =
  printsr [| vis
             Addr.toString wordSize symb.SymAddr
             normalizeEmpty symb.SymName
             getSymbolLibName symb
             symb.SymType.ToString()
             symb.SymDesc.ToString()
             symb.IsExternal.ToString()
             getLibName symb
             String.wrapSqrdBracket (symb.SecNum.ToString()) |]

let makeSymbolsFormatVerbose addrColumn =
  [| LeftAligned 3
     addrColumn
     LeftAligned 40
     LeftAligned 35
     LeftAligned 8
     LeftAligned 11
     LeftAligned 8
     LeftAligned 8
     LeftAligned 9 |]

let makeSymbolsTableHeaderVerbose () =
  [| "S/D"
     "Address"
     "Name"
     "LibName"
     "Type"
     "Description"
     "External"
     "Version"
     "SectIndex" |]

let dumpSymbolsVerbose (mach: MachBinFile) wordSize addrColumn =
  setTableColumnFormats <| makeSymbolsFormatVerbose addrColumn
  printDoubleHorizontalRule ()
  printsr <| makeSymbolsTableHeaderVerbose ()
  printSingleHorizontalRule ()
  mach.StaticSymbols
  |> Array.sortBy (fun s -> s.SymName)
  |> Array.sortBy (fun s -> s.SymAddr)
  |> Array.iter (dumpSymbolVerbose wordSize "(s)")
  mach.DynamicSymbols
  |> Array.sortBy (fun s -> s.SymName)
  |> Array.sortBy (fun s -> s.SymAddr)
  |> Array.iter (dumpSymbolVerbose wordSize "(d)")
  printDoubleHorizontalRule ()
  printsn ""

let makeSymbolsFormatSimple addrColumn =
  [| LeftAligned 3
     LeftAligned 10
     addrColumn
     LeftAligned 55
     LeftAligned 15 |]

let dumpSymbolSimple wordSize vis (symb: Mach.Symbol) =
  printsr [| vis
             $"{symb.SymType}"
             Addr.toString wordSize symb.SymAddr
             normalizeEmpty symb.SymName
             getLibName symb |]

let dumpSymbolsSimple (mach: MachBinFile) wordSize addrColumn =
  setTableColumnFormats <| makeSymbolsFormatSimple addrColumn
  printDoubleHorizontalRule ()
  printsr [| "S/D"; "Kind"; "Address"; "Name"; "Lib Name" |]
  printSingleHorizontalRule ()
  mach.StaticSymbols
  |> Array.sortBy (fun s -> s.SymName)
  |> Array.sortBy (fun s -> s.SymAddr)
  |> Array.iter (dumpSymbolSimple wordSize "(s)")
  mach.DynamicSymbols
  |> Array.sortBy (fun s -> s.SymName)
  |> Array.sortBy (fun s -> s.SymAddr)
  |> Array.iter (dumpSymbolSimple wordSize "(d)")
  printDoubleHorizontalRule ()
  printsn ""

let dumpSymbols (opts: FileViewerOpts) (mach: MachBinFile) =
  let addrColumn = columnWidthOfAddr mach |> LeftAligned
  let wordSize = (mach :> IBinFile).ISA.WordSize
  if opts.Verbose then dumpSymbolsVerbose mach wordSize addrColumn
  else dumpSymbolsSimple mach wordSize addrColumn

let dumpRelocs _ (mach: MachBinFile) =
  let addrColumn = columnWidthOfAddr mach |> LeftAligned
  setTableColumnFormats [| addrColumn; LeftAligned 55; LeftAligned 15 |]
  printDoubleHorizontalRule ()
  printsr [| "Address"; "Name"; "Length" |]
  printSingleHorizontalRule ()
  if mach.Relocations.Length = 0 then
    printsn <| normalizeEmpty ""
  else
    for reloc in mach.Relocations do
      let addr = reloc.RelocSection.SecAddr + uint64 reloc.RelocAddr
      let name = reloc.GetName(mach.Symbols.Values, mach.Sections)
      let len = reloc.RelocAddr
      printsr [| Addr.toString (mach :> IBinFile).ISA.WordSize addr
                 name
                 $"{len}" |]
  printDoubleHorizontalRule ()
  printsn ""

let makeFunctionsFormat addrColumn =
  [| addrColumn
     LeftAligned 55
     LeftAligned 10 |]

let dumpFunction wordSize (symb: Mach.Symbol) =
  printsr [| Addr.toString wordSize symb.SymAddr
             normalizeEmpty symb.SymName
             $"{symb.SymType}" |]

let dumpFunctions _ (mach: MachBinFile) =
  let addrColumn = columnWidthOfAddr mach |> LeftAligned
  let wordSize = (mach :> IBinFile).ISA.WordSize
  setTableColumnFormats <| makeFunctionsFormat addrColumn
  printDoubleHorizontalRule ()
  printsr [| "Address"; "Name"; "Kind" |]
  printSingleHorizontalRule ()
  for addr in (mach :> IBinFile).GetFunctionAddresses() do
    match mach.Symbols.SymbolMap.TryFind addr with
    | Some symb -> dumpFunction wordSize symb
    | None -> ()
  printDoubleHorizontalRule ()
  printsn ""

let dumpArchiveHeader (_: FileViewerOpts) (_: MachBinFile) =
  Terminator.futureFeature ()

let dumpUniversalHeader (_opts: FileViewerOpts) (mach: MachBinFile) =
  let bytes = (mach :> IBinFile).RawBytes
  if Mach.Header.IsFat bytes then
    let archs = Mach.Fat.parseArchs bytes
    for i in 0 .. archs.Length - 1 do
      let arch = archs[i]
      let cpusub = arch.CPUSubType
      printSubsectionTitle <| $"Architecture No. {i.ToString()}"
      resetToDefaultTwoColumnConfig ()
      printsr [| "CPU Type:"; arch.CPUType.ToString() |]
      printsr [| "CPU Subtype:"; "0x" + (uint32 cpusub).ToString("x") |]
      printsr [| "Offset:"; "0x" + arch.Offset.ToString("x") |]
      printsr [| "Size:"; arch.Size.ToString() |]
      printsn ""
  else
    printsn "Not a FAT binary."

let dumpSectionDetails (secName: string) (file: MachBinFile) =
  match file.Sections |> Array.tryFind (fun s -> s.SecName = secName) with
  | Some sec ->
    resetToDefaultTwoColumnConfig ()
    printsr [| "SecName:"; sec.SecName |]
    printsr [| "SegName:"; sec.SegName |]
    printsr [| "SecAddr:"; HexString.ofUInt64 sec.SecAddr |]
    printsr [| "SecSize:"; HexString.ofUInt64 sec.SecSize |]
    printsr [| "SecOffset:"; HexString.ofUInt64 (uint64 sec.SecOffset) |]
    printsr [| "SecAlignment:"; HexString.ofUInt64 (uint64 sec.SecAlignment) |]
    printsr [| "SecRelOff:"; HexString.ofUInt64 (uint64 sec.SecRelOff) |]
    printsr [| "SecNumOfReloc:"; sec.SecNumOfReloc.ToString() |]
    printsr [| "SecType:"; sec.SecType.ToString() |]
    printsr [| "SecAttrib:"; HexString.ofInt32 (int sec.SecAttrib) |]
    for flag in enumerateFlags sec.SecAttrib do
      printsr [| ""; String.ofEnum flag |]
    printsr [| "SecReserved1:"; sec.SecReserved1.ToString() |]
    printsr [| "SecReserved2:"; sec.SecReserved2.ToString() |]
  | None ->
    printsn "Not found."

let dumpSegCmd (mach: MachBinFile) cmd size (seg: Mach.SegCmd) idx =
  printSubsectionTitle <| "Load command " + idx.ToString()
  resetToDefaultTwoColumnConfig ()
  printsr [| "Cmd:"; cmd.ToString() |]
  printsr [| "CmdSize:"; size.ToString() |]
  printsr [| "SegCmdName:"; seg.SegCmdName |]
  printsr [| "VMAddr:"; HexString.ofUInt64 seg.VMAddr |]
  printsr [| "VMSize:"; HexString.ofUInt64 seg.VMSize |]
  printsr [| "FileOff:"; seg.FileOff.ToString() |]
  printsr [| "FileSize:"; seg.FileSize.ToString() |]
  printsr [| "MaxProt:"; HexString.ofUInt64 (uint64 seg.MaxProt) |]
  printsr [| "InitProt:"; HexString.ofUInt64 (uint64 seg.InitProt) |]
  printsr [| "NumSecs:"; seg.NumSecs.ToString() |]
  printsr [| "SegFlag:"; HexString.ofUInt64 (uint64 seg.SegFlag) |]
  printsn ""
  for s in mach.Sections do
    if s.SegName = seg.SegCmdName then
      printSubsubsectionTitle "Section"
      dumpSectionDetails s.SecName mach
      printsn ""
    else
      ()

let dumpSymTabCmd cmd size (symtab: Mach.SymTabCmd) idx =
  printSubsectionTitle <| "Load command " + idx.ToString()
  resetToDefaultTwoColumnConfig ()
  printsr [| "Cmd:"; cmd.ToString() |]
  printsr [| "CmdSize:"; size.ToString() |]
  printsr [| "SymOff:"; HexString.ofUInt64 (uint64 symtab.SymOff) |]
  printsr [| "NumOfSym:"; symtab.NumOfSym.ToString() |]
  printsr [| "StrOff:"; HexString.ofUInt64 (uint64 symtab.StrOff) |]
  printsr [| "StrSize:"; toNBytes (uint64 symtab.StrSize) |]
  printsn ""

let dumpDySymTabCmd cmd size (dysymtab: Mach.DySymTabCmd) idx =
  printSubsectionTitle <| "Load command " + idx.ToString()
  resetToDefaultTwoColumnConfig ()
  printsr [| "Cmd:"; cmd.ToString() |]
  printsr [| "CmdSize:"; size.ToString() |]
  printsr [| "IdxLocalSym:"; dysymtab.IdxLocalSym.ToString() |]
  printsr [| "NumLocalSym:"; dysymtab.NumLocalSym.ToString() |]
  printsr [| "IdxExtSym:"; dysymtab.IdxExtSym.ToString() |]
  printsr [| "NumExtSym:"; dysymtab.NumExtSym.ToString() |]
  printsr [| "IdxUndefSym:"; dysymtab.IdxUndefSym.ToString() |]
  printsr [| "NumUndefSym:"; dysymtab.NumUndefSym.ToString() |]
  printsr [| "TOCOffset:"; dysymtab.TOCOffset.ToString() |]
  printsr [| "NumTOCContents:"; dysymtab.NumTOCContents.ToString() |]
  printsr [| "ModTabOff:"; dysymtab.ModTabOff.ToString() |]
  printsr [| "NumModTab:"; dysymtab.NumModTab.ToString() |]
  printsr [| "ExtRefSymOff:"; dysymtab.ExtRefSymOff.ToString() |]
  printsr [| "NumExtRefSym:"; dysymtab.NumExtRefSym.ToString() |]
  printsr [| "IndirectSymOff:"; dysymtab.IndirectSymOff.ToString() |]
  printsr [| "NumIndirectSym:"; dysymtab.NumIndirectSym.ToString() |]
  printsr [| "ExtRelOff:"; dysymtab.ExtRelOff.ToString() |]
  printsr [| "NumExtRel:"; dysymtab.NumExtRel.ToString() |]
  printsr [| "LocalRelOff:"; dysymtab.LocalRelOff.ToString() |]
  printsr [| "NumLocalRel:"; dysymtab.NumLocalRel.ToString() |]
  printsn ""

let toTimeStampString (v: uint32) =
  DateTime.UnixEpoch.AddSeconds(float v).ToLocalTime().ToString()
  + TimeZoneInfo.Local.ToString()

let dumpDyLibCmd cmd size (dylib: Mach.DyLibCmd) idx =
  printSubsectionTitle <| "Load command " + idx.ToString()
  resetToDefaultTwoColumnConfig ()
  printsr [| "Cmd:"; cmd.ToString() |]
  printsr [| "CmdSize:"; size.ToString() |]
  printsr [| "DyLibName:"; dylib.DyLibName |]
  printsr [| "DyLibTimeStamp:"; toTimeStampString dylib.DyLibTimeStamp |]
  printsr [| "DyLibCurVer:"; toVersionString dylib.DyLibCurVer |]
  printsr [| "DyLibCmpVer:"; toVersionString dylib.DyLibCmpVer |]
  printsn ""

let dumpDyLdInfoCmd cmd size (ldinfo: Mach.DyLdInfoCmd) idx =
  printSubsectionTitle <| "Load command " + idx.ToString()
  resetToDefaultTwoColumnConfig ()
  printsr [| "Cmd:"; cmd.ToString() |]
  printsr [| "CmdSize:"; size.ToString() |]
  printsr [| "RebaseOff:"; ldinfo.RebaseOff.ToString() |]
  printsr [| "RebaseSize:"; ldinfo.RebaseSize.ToString() |]
  printsr [| "BindOff:"; ldinfo.BindOff.ToString() |]
  printsr [| "BindSize:"; ldinfo.BindSize.ToString() |]
  printsr [| "WeakBindOff:"; ldinfo.WeakBindOff.ToString() |]
  printsr [| "WeakBindSize:"; ldinfo.WeakBindSize.ToString() |]
  printsr [| "LazyBindOff:"; ldinfo.LazyBindOff.ToString() |]
  printsr [| "LazyBindSize:"; ldinfo.LazyBindSize.ToString() |]
  printsr [| "ExportOff:"; ldinfo.ExportOff.ToString() |]
  printsr [| "ExportSize:"; ldinfo.ExportSize.ToString() |]
  printsn ""

let dumpFuncStartsCmd (fnstart: Mach.FuncStartsCmd) idx =
  printSubsectionTitle <| "Load command " + idx.ToString()
  resetToDefaultTwoColumnConfig ()
  printsr [| "DataOffset:"; fnstart.DataOffset.ToString() |]
  printsr [| "DataSize:"; fnstart.DataSize.ToString() |]
  printsn ""

let dumpMainCmd cmd size (main: Mach.MainCmd) idx =
  printSubsectionTitle <| "Load command " + idx.ToString()
  resetToDefaultTwoColumnConfig ()
  printsr [| "Cmd:"; cmd.ToString() |]
  printsr [| "CmdSize:"; size.ToString() |]
  printsr [| "EntryOff:"; main.EntryOff.ToString() |]
  printsr [| "StackSize:"; main.StackSize.ToString() |]
  printsn ""

let dumpUnhandledCmd cmd size idx =
  printSubsectionTitle <| "Load command " + idx.ToString()
  resetToDefaultTwoColumnConfig ()
  printsr [| "Cmd:"; cmd.ToString() |]
  printsr [| "CmdSize:"; size.ToString() |]
  printsn ""

let dumpLoadCommands _ (file: MachBinFile) =
  for i in 0 .. file.Commands.Length - 1 do
    match file.Commands[i] with
    | Mach.Segment(cmd, size, seg) ->
      dumpSegCmd file cmd size seg i
    | Mach.SymTab(cmd, size, symtab) ->
      dumpSymTabCmd cmd size symtab i
    | Mach.DySymTab(cmd, size, dysym) ->
      dumpDySymTabCmd cmd size dysym i
    | Mach.DyLib(cmd, size, dylib) ->
      dumpDyLibCmd cmd size dylib i
    | Mach.DyLdInfo(cmd, size, ldinfo) ->
      dumpDyLdInfoCmd cmd size ldinfo i
    | Mach.FuncStarts(_, _, fnstart) ->
      dumpFuncStartsCmd fnstart i
    | Mach.Main(cmd, size, main) ->
      dumpMainCmd cmd size main i
    | Mach.Unhandled(cmd, size) ->
      dumpUnhandledCmd cmd size i

let dumpSharedLibs _ (file: MachBinFile) =
  setTableColumnFormats [| LeftAligned 35; LeftAligned 15; LeftAligned 15 |]
  printDoubleHorizontalRule ()
  printsr [| "Lib Name"; "CurVersion"; "CompatVersion" |]
  printSingleHorizontalRule ()
  for cmd in file.Commands do
    match cmd with
    | Mach.DyLib(_, _, dyLibCmd) ->
      printsr [| dyLibCmd.DyLibName
                 toVersionString dyLibCmd.DyLibCurVer
                 toVersionString dyLibCmd.DyLibCmpVer |]
    | _ -> ()
  printDoubleHorizontalRule ()
  printsn ""

let dumpExceptionTable _ _ =
  Terminator.futureFeature ()
