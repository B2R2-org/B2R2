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

module B2R2.RearEnd.FileViewer.MachViewer

open System
open B2R2
open B2R2.Logging
open B2R2.FrontEnd.BinFile
open B2R2.RearEnd.FileViewer.Helper

let badAccess _ _ = raise InvalidFileFormatException

let translateFlags flags =
  let enumFlags =
    Enum.GetValues(typeof<Mach.MachFlag>) :?> Mach.MachFlag []
    |> Array.toList
  let rec loop acc flags = function
    | [] -> List.rev acc
    | enumFlag :: tail ->
      if uint64 enumFlag &&& flags = uint64 enumFlag then
        loop ((" - " + enumFlag.ToString()) :: acc) flags tail
      else
        loop acc flags tail
  loop [] flags enumFlags

let dumpFileHeader _ (file: MachBinFile) =
  let hdr = file.Header
  Log.Out.TableConfig.ResetDefault()
  Log.Out
  <== [| "Magic:"
         HexString.ofUInt64 (uint64 hdr.Magic)
         + String.wrapParen (hdr.Magic.ToString()) |]
  <== [| "CPU type:"; hdr.CPUType.ToString() |]
  <== [| "CPU subtype:"; HexString.ofInt32 (int hdr.CPUSubType) |]
  <== [| "File type:"; hdr.FileType.ToString() |]
  <== [| "Number of commands:"; hdr.NumCmds.ToString() |]
  <== [| "Size of commands:"; hdr.SizeOfCmds.ToString() |]
  <=/ [| "Flags:"; HexString.ofUInt64 (uint64 hdr.Flags) |]
  translateFlags (uint64 hdr.Flags)
  |> List.iter (fun str -> Log.Out <=/ [| ""; str |])

let translateAttribs attribs =
  let enumAttribs =
    System.Enum.GetValues(typeof<Mach.SectionAttribute>)
    :?> Mach.SectionAttribute []
    |> Array.toList
  let rec loop acc attribs = function
    | [] -> List.rev acc
    | enumAttrib :: tail ->
      if uint64 enumAttrib &&& attribs = uint64 enumAttrib then
        loop ((" - " + enumAttrib.ToString()) :: acc) attribs tail
      else
        loop acc attribs tail
  loop [] attribs enumAttribs

let dumpSectionHeaders (opts: FileViewerOpts) (mach: MachBinFile) =
  let addrColumn = columnWidthOfAddr mach |> LeftAligned
  let file = mach :> IBinFile
  if opts.Verbose then
    Log.Out.TableConfig.Columns <- [| LeftAligned 4
                                      addrColumn
                                      addrColumn
                                      LeftAligned 16
                                      LeftAligned 8
                                      LeftAligned 8
                                      LeftAligned 8
                                      LeftAligned 8
                                      LeftAligned 10
                                      LeftAligned 6
                                      LeftAligned 22
                                      LeftAligned 4
                                      LeftAligned 4
                                      LeftAligned 8 |]
    Log.Out
    <== [| "Num"
           "Start"
           "End"
           "Name"
           "SegName"
           "Size"
           "Offset"
           "Align"
           "SecRelOff"
           "#Reloc"
           "Type"
           "Res1"
           "Res2"
           "Attrib" |]
    <=/ "  ---"
    mach.Sections
    |> Array.iteri (fun idx s ->
      Log.Out
      <=/ [| String.wrapSqrdBracket (idx.ToString())
             Addr.toString file.ISA.WordSize s.SecAddr
             Addr.toString file.ISA.WordSize (s.SecAddr + s.SecSize - uint64 1)
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
      translateAttribs (uint64 s.SecAttrib)
      |> List.iter (fun str ->
        Log.Out <=/
          [| ""; ""; ""; ""; ""; ""; ""; ""; ""; ""; ""; ""; ""; str |])
    )
  else
    let colfmt = [| LeftAligned 4; addrColumn; addrColumn; LeftAligned 24 |]
    Log.Out.TableConfig.Columns <- colfmt
    Log.Out
    <== [| "Num"; "Start"; "End"; "Name" |]
    <=/ "  ---"
    mach.Sections
    |> Array.iteri (fun idx s ->
      Log.Out <=/
        [| String.wrapSqrdBracket (idx.ToString())
           Addr.toString file.ISA.WordSize s.SecAddr
           Addr.toString file.ISA.WordSize (s.SecAddr + uint64 s.SecSize - 1UL)
           normalizeEmpty s.SecName |]
    )

let dumpSectionDetails (secName: string) (file: MachBinFile) =
  match file.Sections |> Array.tryFind (fun s -> s.SecName = secName) with
  | Some section ->
    Log.Out.TableConfig.ResetDefault()
    Log.Out
    <== [| "SecName:"; section.SecName |]
    <== [| "SegName:"; section.SegName |]
    <== [| "SecAddr:"; HexString.ofUInt64 section.SecAddr |]
    <== [| "SecSize:"; HexString.ofUInt64 section.SecSize |]
    <== [| "SecOffset:"; HexString.ofUInt64 (uint64 section.SecOffset) |]
    <== [| "SecAlignment:"; HexString.ofUInt64 (uint64 section.SecAlignment) |]
    <== [| "SecRelOff:"; HexString.ofUInt64 (uint64 section.SecRelOff) |]
    <== [| "SecNumOfReloc:"; section.SecNumOfReloc.ToString() |]
    <== [| "SecType:"; section.SecType.ToString() |]
    <=/ [| "SecAttrib:"; HexString.ofInt32 (int section.SecAttrib) |]
    translateAttribs (uint64 section.SecAttrib)
    |> List.iter (fun str -> Log.Out <=/ [| ""; str |])
    Log.Out
    <== [| "SecReserved1:"; section.SecReserved1.ToString() |]
    <=/ [| "SecReserved2:"; section.SecReserved2.ToString() |]
  | None ->
    Log.Out.PrintLine "Not found."

let toVersionString (v: uint32) =
  let major = (v &&& uint32 0xFFFF0000) >>> 16
  let minor1 = (v &&& uint32 0x0000FF00) >>> 8
  let minor2 = v &&& uint32 0x000000FF
  major.ToString() + "." + minor1.ToString() + "." + minor2.ToString()

let getSymbolLibName (symbol: Mach.Symbol) =
  match symbol.VerInfo with
  | None -> ""
  | Some v -> toLibString v.DyLibName |> normalizeEmpty

let getLibName (symb: Mach.Symbol) =
  match symb.VerInfo with
  | Some info ->
    info.DyLibName
    + String.wrapParen
      "compatibility version " + toVersionString info.DyLibCmpVer + ", "
      + "current version" + toVersionString info.DyLibCurVer
  | None -> "(n/a)"

let printSymbolInfoVerbose file (symb: Mach.Symbol) vis =
  Log.Out
  <=/ [| vis
         Addr.toString (file: IBinFile).ISA.WordSize symb.SymAddr
         normalizeEmpty symb.SymName
         getSymbolLibName symb
         symb.SymType.ToString()
         symb.SymDesc.ToString()
         symb.IsExternal.ToString()
         getLibName symb
         String.wrapSqrdBracket (symb.SecNum.ToString())
         ""
         ""
         "" |]

let printSymbolInfoNonVerbose mach (symb: Mach.Symbol) vis =
  Log.Out
  <=/ [| vis
         $"{symb.SymType}"
         Addr.toString (mach :> IBinFile).ISA.WordSize symb.SymAddr
         normalizeEmpty symb.SymName
         getLibName symb |]

let printSymbolInfo isVerbose (mach: MachBinFile) =
  let addrColumn = columnWidthOfAddr mach |> LeftAligned
  if isVerbose then
    Log.Out.TableConfig.Columns <- [| LeftAligned 3
                                      addrColumn
                                      LeftAligned 40
                                      LeftAligned 35
                                      LeftAligned 8
                                      LeftAligned 8
                                      LeftAligned 8
                                      LeftAligned 8
                                      LeftAligned 8 |]
    Log.Out
    <== [| "S/D"
           "Address"
           "Name"
           "Lib Name"
           "Type"
           "Description"
           "External"
           "Version"
           "SectionIndex" |]
    <=/ "  ---"
    mach.StaticSymbols
    |> Array.sortBy (fun s -> s.SymName)
    |> Array.sortBy (fun s -> s.SymAddr)
    |> Array.iter (fun s -> printSymbolInfoVerbose mach s "(s)")
    mach.DynamicSymbols
    |> Array.sortBy (fun s -> s.SymName)
    |> Array.sortBy (fun s -> s.SymAddr)
    |> Array.iter (fun s -> printSymbolInfoVerbose mach s "(d)")
  else
    Log.Out.TableConfig.Columns <- [| LeftAligned 3
                                      LeftAligned 10
                                      addrColumn
                                      LeftAligned 55
                                      LeftAligned 15 |]
    Log.Out
    <== [| "S/D"; "Kind"; "Address"; "Name"; "Lib Name" |]
    <=/ "  ---"
    mach.StaticSymbols
    |> Array.sortBy (fun s -> s.SymName)
    |> Array.sortBy (fun s -> s.SymAddr)
    |> Array.iter (fun s -> printSymbolInfoNonVerbose mach s "(s)")
    mach.DynamicSymbols
    |> Array.sortBy (fun s -> s.SymName)
    |> Array.sortBy (fun s -> s.SymAddr)
    |> Array.iter (fun s -> printSymbolInfoNonVerbose mach s "(d)")

let dumpSymbols (opts: FileViewerOpts) (mach: MachBinFile) =
  printSymbolInfo opts.Verbose mach

let dumpRelocs (_: FileViewerOpts) (mach: MachBinFile) =
  let addrColumn = columnWidthOfAddr mach |> LeftAligned
  let colfmt = [| addrColumn; LeftAligned 55; LeftAligned 15 |]
  Log.Out.TableConfig.Columns <- colfmt
  Log.Out
  <=/ [| "Address"; "Name"; "Length" |]
  for reloc in mach.Relocations do
    let addr = reloc.RelocSection.SecAddr + uint64 reloc.RelocAddr
    let name = reloc.GetName(mach.Symbols.Values, mach.Sections)
    let len = reloc.RelocAddr
    Log.Out
    <=/ [| Addr.toString (mach :> IBinFile).ISA.WordSize addr
           name
           $"{len}" |]

let dumpFunctions (opts: FileViewerOpts) (mach: MachBinFile) =
  let addrColumn = columnWidthOfAddr mach |> LeftAligned
  Log.Out.TableConfig.Columns <- [| LeftAligned 3
                                    LeftAligned 10
                                    addrColumn
                                    LeftAligned 55
                                    LeftAligned 15 |]
  for addr in (mach :> IBinFile).GetFunctionAddresses() do
    match mach.Symbols.SymbolMap.TryFind addr with
    | Some symb -> printSymbolInfoNonVerbose mach symb ""
    | None -> ()

let dumpArchiveHeader (opts: FileViewerOpts) (file: MachBinFile) =
  Terminator.futureFeature ()

let dumpUniversalHeader (_opts: FileViewerOpts) (mach: MachBinFile) =
  let bytes = IBinFile.Slice(mach, 0, 4).ToArray()
  if Mach.Header.IsFat bytes then
    Mach.Fat.parseArchs bytes
    |> Array.iteri (fun idx fat ->
      let cpu = fat.CPUType
      let cpusub = fat.CPUSubType
      Log.Out.PrintSubsectionTitle("Architecture #" + idx.ToString())
      Log.Out.TableConfig.ResetDefault()
      Log.Out
      <== [| "CPU Type:"; cpu.ToString() |]
      <== [| "CPU Subtype:"; "0x" + (uint32 cpusub).ToString("x") |]
      <== [| "Offset:"; "0x" + fat.Offset.ToString("x") |]
      <=/ [| "Size:"; fat.Size.ToString() |]
    )
  else printfn "Not a FAT binary."

let printSegCmd cmd size (seg: Mach.SegCmd) idx =
  Log.Out.PrintSubsectionTitle("Load command " + idx.ToString())
  Log.Out.TableConfig.ResetDefault()
  Log.Out
  <== [| "Cmd:"; cmd.ToString() |]
  <== [| "CmdSize:"; size.ToString() |]
  <== [| "SegCmdName:"; seg.SegCmdName |]
  <== [| "VMAddr:"; HexString.ofUInt64 seg.VMAddr |]
  <== [| "VMSize:"; HexString.ofUInt64 seg.VMSize |]
  <== [| "FileOff:"; seg.FileOff.ToString() |]
  <== [| "FileSize:"; seg.FileSize.ToString() |]
  <== [| "MaxProt:"; HexString.ofUInt64 (uint64 seg.MaxProt) |]
  <== [| "InitProt:"; HexString.ofUInt64 (uint64 seg.InitProt) |]
  <== [| "NumSecs:"; seg.NumSecs.ToString() |]
  <=/ [| "SegFlag:"; HexString.ofUInt64 (uint64 seg.SegFlag) |]

let printSymTabCmd cmd size (symtab: Mach.SymTabCmd) idx =
  Log.Out.PrintSubsectionTitle("Load command " + idx.ToString())
  Log.Out.TableConfig.ResetDefault()
  Log.Out
  <== [| "Cmd:"; cmd.ToString() |]
  <== [| "CmdSize:"; size.ToString() |]
  <== [| "SymOff:"; HexString.ofUInt64 (uint64 symtab.SymOff) |]
  <== [| "NumOfSym:"; symtab.NumOfSym.ToString() |]
  <== [| "StrOff:"; HexString.ofUInt64 (uint64 symtab.StrOff) |]
  <=/ [| "StrSize:"; toNBytes (uint64 symtab.StrSize) |]

let printDySymTabCmd cmd size (dysymtab: Mach.DySymTabCmd) idx =
  Log.Out.PrintSubsectionTitle("Load command " + idx.ToString())
  Log.Out.TableConfig.ResetDefault()
  Log.Out
  <== [| "Cmd:"; cmd.ToString() |]
  <== [| "CmdSize:"; size.ToString() |]
  <== [| "IdxLocalSym:"; dysymtab.IdxLocalSym.ToString() |]
  <== [| "NumLocalSym:"; dysymtab.NumLocalSym.ToString() |]
  <== [| "IdxExtSym:"; dysymtab.IdxExtSym.ToString() |]
  <== [| "NumExtSym:"; dysymtab.NumExtSym.ToString() |]
  <== [| "IdxUndefSym:"; dysymtab.IdxUndefSym.ToString() |]
  <== [| "NumUndefSym:"; dysymtab.NumUndefSym.ToString() |]
  <== [| "TOCOffset:"; dysymtab.TOCOffset.ToString() |]
  <== [| "NumTOCContents:"; dysymtab.NumTOCContents.ToString() |]
  <== [| "ModTabOff:"; dysymtab.ModTabOff.ToString() |]
  <== [| "NumModTab:"; dysymtab.NumModTab.ToString() |]
  <== [| "ExtRefSymOff:"; dysymtab.ExtRefSymOff.ToString() |]
  <== [| "NumExtRefSym:"; dysymtab.NumExtRefSym.ToString() |]
  <== [| "IndirectSymOff:"; dysymtab.IndirectSymOff.ToString() |]
  <== [| "NumIndirectSym:"; dysymtab.NumIndirectSym.ToString() |]
  <== [| "ExtRelOff:"; dysymtab.ExtRelOff.ToString() |]
  <== [| "NumExtRel:"; dysymtab.NumExtRel.ToString() |]
  <== [| "LocalRelOff:"; dysymtab.LocalRelOff.ToString() |]
  <=/ [| "NumLocalRel:"; dysymtab.NumLocalRel.ToString() |]

let toTimeStampString (v: uint32) =
  DateTime.UnixEpoch.AddSeconds(float v).ToLocalTime().ToString()
  + TimeZoneInfo.Local.ToString()

let printDyLibCmd cmd size (dylib: Mach.DyLibCmd) idx =
  Log.Out.PrintSubsectionTitle("Load command " + idx.ToString())
  Log.Out.TableConfig.ResetDefault()
  Log.Out
  <== [| "Cmd:"; cmd.ToString() |]
  <== [| "CmdSize:"; size.ToString() |]
  <== [| "DyLibName:"; dylib.DyLibName |]
  <== [| "DyLibTimeStamp:"; toTimeStampString dylib.DyLibTimeStamp |]
  <== [| "DyLibCurVer:"; toVersionString dylib.DyLibCurVer |]
  <=/ [| "DyLibCmpVer:"; toVersionString dylib.DyLibCmpVer |]

let printDyLdInfoCmd cmd size (ldinfo: Mach.DyLdInfoCmd) idx =
  Log.Out.PrintSubsectionTitle("Load command " + idx.ToString())
  Log.Out.TableConfig.ResetDefault()
  Log.Out
  <== [| "Cmd:"; cmd.ToString() |]
  <== [| "CmdSize:"; size.ToString() |]
  <== [| "RebaseOff:"; ldinfo.RebaseOff.ToString() |]
  <== [| "RebaseSize:"; ldinfo.RebaseSize.ToString() |]
  <== [| "BindOff:"; ldinfo.BindOff.ToString() |]
  <== [| "BindSize:"; ldinfo.BindSize.ToString() |]
  <== [| "WeakBindOff:"; ldinfo.WeakBindOff.ToString() |]
  <== [| "WeakBindSize:"; ldinfo.WeakBindSize.ToString() |]
  <== [| "LazyBindOff:"; ldinfo.LazyBindOff.ToString() |]
  <== [| "LazyBindSize:"; ldinfo.LazyBindSize.ToString() |]
  <== [| "ExportOff:"; ldinfo.ExportOff.ToString() |]
  <=/ [| "ExportSize:"; ldinfo.ExportSize.ToString() |]

let printFuncStartsCmd (fnstart: Mach.FuncStartsCmd) idx =
  Log.Out.PrintSubsectionTitle("Load command " + idx.ToString())
  Log.Out.TableConfig.ResetDefault()
  Log.Out
  <== [| "DataOffset:"; fnstart.DataOffset.ToString() |]
  <=/ [| "DataSize:"; fnstart.DataSize.ToString() |]

let printMainCmd cmd size (main: Mach.MainCmd) idx =
  Log.Out.PrintSubsectionTitle("Load command " + idx.ToString())
  Log.Out.TableConfig.ResetDefault()
  Log.Out
  <== [| "Cmd:"; cmd.ToString() |]
  <== [| "CmdSize:"; size.ToString() |]
  <== [| "EntryOff:"; main.EntryOff.ToString() |]
  <=/ [| "StackSize:"; main.StackSize.ToString() |]

let printUnhandledCmd cmd size idx =
  Log.Out.PrintSubsectionTitle("Load command " + idx.ToString())
  Log.Out.TableConfig.ResetDefault()
  Log.Out
  <== [| "Cmd:"; cmd.ToString() |]
  <=/ [| "CmdSize:"; size.ToString() |]

let dumpLoadCommands _ (file: MachBinFile) =
  file.Commands
  |> Array.iteri (fun idx cmd ->
    match cmd with
    | Mach.Segment(cmd, size, seg) ->
      printSegCmd cmd size seg idx
      file.Sections
      |> Array.iter (fun s ->
        if s.SegName = seg.SegCmdName then
          Log.Out.PrintLine()
          Log.Out.PrintSubsubsectionTitle(String.wrapSqrdBracket "Section")
          dumpSectionDetails s.SecName file
        else
          ())
    | Mach.SymTab(cmd, size, symtab) -> printSymTabCmd cmd size symtab idx
    | Mach.DySymTab(cmd, size, dysym) -> printDySymTabCmd cmd size dysym idx
    | Mach.DyLib(cmd, size, dylib) -> printDyLibCmd cmd size dylib idx
    | Mach.DyLdInfo(cmd, size, ldinfo) -> printDyLdInfoCmd cmd size ldinfo idx
    | Mach.FuncStarts(_, _, fnstart) -> printFuncStartsCmd fnstart idx
    | Mach.Main(cmd, size, main) -> printMainCmd cmd size main idx
    | Mach.Unhandled(cmd, size) -> printUnhandledCmd cmd size idx
    Log.Out.PrintLine())

let dumpSharedLibs _ (file: MachBinFile) =
  let colfmt = [| LeftAligned 35; LeftAligned 15; LeftAligned 15 |]
  Log.Out.TableConfig.Columns <- colfmt
  Log.Out <=/ [| "Lib Name"; "CurVersion"; "CompatVersion" |]
  file.Commands
  |> Array.iter (fun cmd ->
    match cmd with
    | Mach.DyLib(_, _, dyLibCmd) ->
      Log.Out
      <=/ [| dyLibCmd.DyLibName
             toVersionString dyLibCmd.DyLibCurVer
             toVersionString dyLibCmd.DyLibCmpVer |]
    | _ -> ())
