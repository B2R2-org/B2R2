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
open B2R2.FrontEnd.BinFile
open B2R2.RearEnd.FileViewer.Helper

let badAccess _ _ =
  raise InvalidFileFormatException

let translateFlags flags =
  let enumFlags =
    Enum.GetValues (typeof<Mach.MachFlag>) :?> Mach.MachFlag []
    |> Array.toList
  let rec loop acc flags = function
    | [] -> List.rev acc
    | enumFlag :: tail ->
      if uint64 enumFlag &&& flags = uint64 enumFlag then
        loop ((" - " + enumFlag.ToString ()) :: acc) flags tail
      else
        loop acc flags tail
  loop [] flags enumFlags

let dumpFileHeader _ (file: MachBinFile) =
  let hdr = file.Mach.MachHdr
  out.PrintTwoCols
    "Magic:"
    (String.u64ToHex (uint64 hdr.Magic)
    + String.wrapParen (hdr.Magic.ToString ()))
  out.PrintTwoCols
    "Cpu type:"
    (hdr.CPUType.ToString ())
  out.PrintTwoCols
    "Cpu subtype:"
    (String.u32ToHex (uint32 hdr.CPUSubType))
  out.PrintTwoCols
    "File type:"
    (hdr.FileType.ToString ())
  out.PrintTwoCols
    "Number of commands:"
    (hdr.NumCmds.ToString ())
  out.PrintTwoCols
    "Size of commands:"
    (hdr.SizeOfCmds.ToString ())
  out.PrintTwoCols
    "Flags:"
    (String.u64ToHex (uint64 hdr.Flags))
  translateFlags (uint64 hdr.Flags)
  |> List.iter (fun str -> out.PrintTwoCols "" str)

let translateAttribs attribs =
  let enumAttribs =
    System.Enum.GetValues (typeof<Mach.SectionAttribute>)
    :?> Mach.SectionAttribute []
    |> Array.toList
  let rec loop acc attribs = function
    | [] -> List.rev acc
    | enumAttrib :: tail ->
      if uint64 enumAttrib &&& attribs = uint64 enumAttrib then
        loop ((" - " + enumAttrib.ToString ()) :: acc) attribs tail
      else
        loop acc attribs tail
  loop [] attribs enumAttribs

let dumpSectionHeaders (opts: FileViewerOpts) (file: MachBinFile) =
  let addrColumn = columnWidthOfAddr file |> LeftAligned
  if opts.Verbose then
    let cfg = [ LeftAligned 4; addrColumn; addrColumn; LeftAligned 16
                LeftAligned 8; LeftAligned 8; LeftAligned 8; LeftAligned 8
                LeftAligned 10; LeftAligned 6; LeftAligned 22
                LeftAligned 4; LeftAligned 4; LeftAligned 8 ]
    out.PrintRow (true, cfg, [ "Num"; "Start"; "End"; "Name"
                               "SegName"; "Size"; "Offset"; "Align"
                               "SecRelOff"; "#Reloc"; "Type"
                               "Res1"; "Res2"; "Attrib" ])
    out.PrintLine "  ---"
    file.Mach.Sections.SecByNum
    |> Array.iteri (fun idx s ->
      out.PrintRow (true, cfg,
        [ String.wrapSqrdBracket (idx.ToString ())
          (Addr.toString file.WordSize s.SecAddr)
          (Addr.toString file.WordSize (s.SecAddr + s.SecSize - uint64 1))
          normalizeEmpty s.SecName
          normalizeEmpty s.SegName
          String.u64ToHex s.SecSize
          String.u64ToHex (uint64 s.SecOffset)
          String.u64ToHex (uint64 s.SecAlignment)
          s.SecRelOff.ToString ()
          s.SecNumOfReloc.ToString ()
          s.SecType.ToString ()
          s.SecReserved1.ToString ()
          s.SecReserved2.ToString ()
          String.u32ToHex (uint32 s.SecAttrib) ])
      translateAttribs (uint64 s.SecAttrib)
      |> List.iter (fun str ->
        out.PrintRow (true, cfg, [ ""; ""; ""; ""; ""; ""; ""; ""; ""
                                   ""; ""; ""; ""; str ]))
    )
  else
    let cfg = [ LeftAligned 4; addrColumn; addrColumn; LeftAligned 24 ]
    out.PrintRow (true, cfg, [ "Num"; "Start"; "End"; "Name" ])
    out.PrintLine "  ---"
    file.GetSections ()
    |> Seq.iteri (fun idx s ->
      out.PrintRow (true, cfg,
        [ String.wrapSqrdBracket (idx.ToString ())
          (Addr.toString file.WordSize s.Address)
          (Addr.toString file.WordSize (s.Address + s.Size - uint64 1))
          normalizeEmpty s.Name ]))

let dumpSectionDetails (secname: string) (file: MachBinFile) =
  match file.Mach.Sections.SecByName.TryFind secname with
  | Some section ->
    out.PrintTwoCols
      "SecName:"
      section.SecName
    out.PrintTwoCols
      "SegName:"
      section.SegName
    out.PrintTwoCols
      "SecAddr:"
      (String.u64ToHex section.SecAddr)
    out.PrintTwoCols
      "SecSize:"
      (String.u64ToHex section.SecSize)
    out.PrintTwoCols
      "SecOffset:"
      (String.u64ToHex (uint64 section.SecOffset))
    out.PrintTwoCols
      "SecAlignment:"
      (String.u64ToHex (uint64 section.SecAlignment))
    out.PrintTwoCols
      "SecRelOff:"
      (String.u64ToHex (uint64 section.SecRelOff))
    out.PrintTwoCols
      "SecNumOfReloc:"
      (section.SecNumOfReloc.ToString ())
    out.PrintTwoCols
      "SecType:"
      (section.SecType.ToString ())
    out.PrintTwoCols
      "SecAttrib:"
      (String.u32ToHex (uint32 section.SecAttrib))
    translateAttribs (uint64 section.SecAttrib)
    |> List.iter (fun str -> out.PrintTwoCols "" str )
    out.PrintTwoCols
      "SecReserved1:"
      (section.SecReserved1.ToString ())
    out.PrintTwoCols
      "SecReserved2:"
      (section.SecReserved2.ToString ())
  | None -> out.PrintLine "Not found."

let toVersionString (v: uint32) =
  let major = (v &&& uint32 0xFFFF0000) >>> 16
  let minor1 = (v &&& uint32 0x0000FF00) >>> 8
  let minor2 = v &&& uint32 0x000000FF
  major.ToString () + "." + minor1.ToString () + "." + minor2.ToString ()

let printSymbolInfoVerbose file s (machSymbol: Mach.MachSymbol) cfg =
  let externLibVerinfo =
    match machSymbol.VerInfo with
    | Some info ->
      info.DyLibName
      + String.wrapParen
        "compatibility version " + toVersionString info.DyLibCmpVer + ", "
        + "current version" + toVersionString info.DyLibCurVer
    | None -> "(n/a)"
  out.PrintRow (true, cfg,
    [ visibilityString s
      Addr.toString (file: MachBinFile).WordSize s.Address
      normalizeEmpty s.Name
      (toLibString >> normalizeEmpty) s.LibraryName
      machSymbol.SymType.ToString ()
      machSymbol.SymDesc.ToString ()
      machSymbol.IsExternal.ToString ()
      externLibVerinfo
      String.wrapSqrdBracket (machSymbol.SecNum.ToString ()); ""; ""; "" ])

let printSymbolInfoNone file s cfg =
  out.PrintRow (true, cfg,
    [ visibilityString s
      Addr.toString (file: MachBinFile).WordSize s.Address
      normalizeEmpty s.Name
      (toLibString >> normalizeEmpty) s.LibraryName
      "(n/a)"; "(n/a)"; "(n/a)"; "(n/a)"; "(n/a)" ])

let printSymbolInfo isVerbose (file: MachBinFile) (symbols: seq<Symbol>) =
  let addrColumn = columnWidthOfAddr file |> LeftAligned
  if isVerbose then
    let cfg = [ LeftAligned 3; addrColumn; LeftAligned 40; LeftAligned 35
                LeftAligned 8; LeftAligned 8; LeftAligned 8; LeftAligned 8
                LeftAligned 8 ]
    out.PrintRow (true, cfg, [ "S/D"; "Address"; "Name"; "Lib Name"
                               "Type"; "Description"; "External"; "Version"
                               "SectionIndex" ])
    out.PrintLine "  ---"
    symbols
    |> Seq.sortBy (fun s -> s.Name)
    |> Seq.sortBy (fun s -> s.Address)
    |> Seq.sortBy (fun s -> s.Visibility)
    |> Seq.iter (fun s ->
      match file.Mach.SymInfo.SymbolMap.TryFind s.Address with
      | Some machSymbol -> printSymbolInfoVerbose file s machSymbol cfg
      | None -> printSymbolInfoNone file s cfg)
  else
    let cfg = [ LeftAligned 3; LeftAligned 10
                addrColumn; LeftAligned 55; LeftAligned 15 ]
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
          Addr.toString file.WordSize s.Address
          normalizeEmpty s.Name
          (toLibString >> normalizeEmpty) s.LibraryName ]))

let dumpSymbols (opts: FileViewerOpts) (file: MachBinFile) =
  file.GetSymbols ()
  |> printSymbolInfo opts.Verbose file

let dumpRelocs (opts: FileViewerOpts) (file: MachBinFile) =
  file.GetRelocationSymbols ()
  |> printSymbolInfo opts.Verbose file

let dumpFunctions (opts: FileViewerOpts) (file: MachBinFile) =
  file.GetFunctionSymbols ()
  |> printSymbolInfo opts.Verbose file

let dumpArchiveHeader (opts: FileViewerOpts) (file: MachBinFile) =
  Utils.futureFeature ()

let dumpUniversalHeader (_opts: FileViewerOpts) (file: MachBinFile) =
  let span = file.Span
  let reader = file.Mach.BinReader
  if Mach.Header.isFat span reader then
    Mach.Fat.loadFats span reader
    |> List.iteri (fun idx fat ->
      let cpu = fat.CPUType
      let cpusub = fat.CPUSubType
      let arch = Mach.Header.cpuTypeToArch cpu cpusub
      out.PrintSubsectionTitle ("Architecture #" + idx.ToString ())
      out.PrintTwoCols "CPU Type:" (cpu.ToString ())
      out.PrintTwoCols "CPU Subtype:" ("0x" + (uint32 cpusub).ToString ("x"))
      out.PrintTwoCols "Architecture:" (ISA.ArchToString arch)
      out.PrintTwoCols "Offset:" ("0x" + fat.Offset.ToString ("x"))
      out.PrintTwoCols "Size:" (fat.Size.ToString ())
    )
  else printfn "Not a FAT binary."

let printSegCmd (segCmd: Mach.SegCmd) idx =
  out.PrintSubsectionTitle ("Load command " + idx.ToString ())
  out.PrintTwoCols "Cmd:" (segCmd.Cmd.ToString ())
  out.PrintTwoCols "CmdSize:" (segCmd.CmdSize.ToString ())
  out.PrintTwoCols "SegCmdName:" segCmd.SegCmdName
  out.PrintTwoCols "VMAddr:" (String.u64ToHex segCmd.VMAddr)
  out.PrintTwoCols "VMSize:" (String.u64ToHex segCmd.VMSize)
  out.PrintTwoCols "FileOff:" (segCmd.FileOff.ToString ())
  out.PrintTwoCols "FileSize:" (segCmd.FileSize.ToString ())
  out.PrintTwoCols "MaxProt:" (String.u64ToHex (uint64 segCmd.MaxProt))
  out.PrintTwoCols "InitProt:" (String.u64ToHex (uint64 segCmd.InitProt))
  out.PrintTwoCols "NumSecs:" (segCmd.NumSecs.ToString ())
  out.PrintTwoCols "SegFlag:" (String.u64ToHex (uint64 segCmd.SegFlag))

let printSymTabCmd (symTabCmd: Mach.SymTabCmd) idx =
  out.PrintSubsectionTitle ("Load command " + idx.ToString ())
  out.PrintTwoCols "Cmd:" (symTabCmd.Cmd.ToString ())
  out.PrintTwoCols "CmdSize:" (symTabCmd.CmdSize.ToString ())
  out.PrintTwoCols "SymOff:" (String.u64ToHex (uint64 symTabCmd.SymOff))
  out.PrintTwoCols "NumOfSym:" (symTabCmd.NumOfSym.ToString ())
  out.PrintTwoCols "StrOff:" (String.u64ToHex (uint64 symTabCmd.StrOff))
  out.PrintTwoCols "StrSize:" (toNBytes (uint64 symTabCmd.StrSize))

let printDySymTabCmd (dySymTabCmd: Mach.DySymTabCmd) idx =
  out.PrintSubsectionTitle ("Load command " + idx.ToString ())
  out.PrintTwoCols "Cmd:" (dySymTabCmd.Cmd.ToString ())
  out.PrintTwoCols "CmdSize:" (dySymTabCmd.CmdSize.ToString ())
  out.PrintTwoCols "IdxLocalSym:" (dySymTabCmd.IdxLocalSym.ToString ())
  out.PrintTwoCols "NumLocalSym:" (dySymTabCmd.NumLocalSym.ToString ())
  out.PrintTwoCols "IdxExtSym:" (dySymTabCmd.IdxExtSym.ToString ())
  out.PrintTwoCols "NumExtSym:" (dySymTabCmd.NumExtSym.ToString ())
  out.PrintTwoCols "IdxUndefSym:" (dySymTabCmd.IdxUndefSym.ToString ())
  out.PrintTwoCols "NumUndefSym:" (dySymTabCmd.NumUndefSym.ToString ())
  out.PrintTwoCols "TOCOffset:" (dySymTabCmd.TOCOffset.ToString ())
  out.PrintTwoCols "NumTOCContents:" (dySymTabCmd.NumTOCContents.ToString ())
  out.PrintTwoCols "ModTabOff:" (dySymTabCmd.ModTabOff.ToString ())
  out.PrintTwoCols "NumModTab:" (dySymTabCmd.NumModTab.ToString ())
  out.PrintTwoCols "ExtRefSymOff:" (dySymTabCmd.ExtRefSymOff.ToString ())
  out.PrintTwoCols "NumExtRefSym:" (dySymTabCmd.NumExtRefSym.ToString ())
  out.PrintTwoCols "IndirectSymOff:" (dySymTabCmd.IndirectSymOff.ToString ())
  out.PrintTwoCols "NumIndirectSym:" (dySymTabCmd.NumIndirectSym.ToString ())
  out.PrintTwoCols "ExtRelOff:" (dySymTabCmd.ExtRelOff.ToString ())
  out.PrintTwoCols "NumExtRel:" (dySymTabCmd.NumExtRel.ToString ())
  out.PrintTwoCols "LocalRelOff:" (dySymTabCmd.LocalRelOff.ToString ())
  out.PrintTwoCols "NumLocalRel:" (dySymTabCmd.NumLocalRel.ToString ())

let toTimeStampString (v: uint32) =
  ((DateTime.UnixEpoch.AddSeconds (float v)).ToLocalTime ()).ToString ()
  + TimeZoneInfo.Local.ToString ()

let printDyLibCmd (dyLibCmd: Mach.DyLibCmd) idx =
  out.PrintSubsectionTitle ("Load command " + idx.ToString ())
  out.PrintTwoCols "Cmd:" (dyLibCmd.Cmd.ToString ())
  out.PrintTwoCols "CmdSize:" (dyLibCmd.CmdSize.ToString ())
  out.PrintTwoCols "DyLibName:" dyLibCmd.DyLibName
  out.PrintTwoCols "DyLibTimeStamp:" (toTimeStampString dyLibCmd.DyLibTimeStamp)
  out.PrintTwoCols "DyLibCurVer:" (toVersionString dyLibCmd.DyLibCurVer)
  out.PrintTwoCols "DyLibCmpVer:" (toVersionString dyLibCmd.DyLibCmpVer)

let printDyLdInfoCmd (dyLdInfoCmd: Mach.DyLdInfoCmd) idx =
  out.PrintSubsectionTitle ("Load command " + idx.ToString ())
  out.PrintTwoCols "Cmd:" (dyLdInfoCmd.Cmd.ToString ())
  out.PrintTwoCols "CmdSize:" (dyLdInfoCmd.CmdSize.ToString ())
  out.PrintTwoCols "RebaseOff:" (dyLdInfoCmd.RebaseOff.ToString ())
  out.PrintTwoCols "RebaseSize:" (dyLdInfoCmd.RebaseSize.ToString ())
  out.PrintTwoCols "BindOff:" (dyLdInfoCmd.BindOff.ToString ())
  out.PrintTwoCols "BindSize:" (dyLdInfoCmd.BindSize.ToString ())
  out.PrintTwoCols "WeakBindOff:" (dyLdInfoCmd.WeakBindOff.ToString ())
  out.PrintTwoCols "WeakBindSize:" (dyLdInfoCmd.WeakBindSize.ToString ())
  out.PrintTwoCols "LazyBindOff:" (dyLdInfoCmd.LazyBindOff.ToString ())
  out.PrintTwoCols "LazyBindSize:" (dyLdInfoCmd.LazyBindSize.ToString ())
  out.PrintTwoCols "ExportOff:" (dyLdInfoCmd.ExportOff.ToString ())
  out.PrintTwoCols "ExportSize:" (dyLdInfoCmd.ExportSize.ToString ())

let printFuncStartsCmd (funcStartsCmd: Mach.FuncStartsCmd) idx =
  out.PrintSubsectionTitle ("Load command " + idx.ToString ())
  out.PrintTwoCols "DataOffset:" (funcStartsCmd.DataOffset.ToString ())
  out.PrintTwoCols "DataSize:" (funcStartsCmd.DataSize.ToString ())

let printMainCmd (mainCmd: Mach.MainCmd) idx =
  out.PrintSubsectionTitle ("Load command " + idx.ToString ())
  out.PrintTwoCols "Cmd:" (mainCmd.Cmd.ToString ())
  out.PrintTwoCols "CmdSize:" (mainCmd.CmdSize.ToString ())
  out.PrintTwoCols "EntryOff:" (mainCmd.EntryOff.ToString ())
  out.PrintTwoCols "StackSize:" (mainCmd.StackSize.ToString ())

let printUnhandledCmd (unhandledCmd: Mach.UnhandledCommand) idx =
  out.PrintSubsectionTitle ("Load command " + idx.ToString ())
  out.PrintTwoCols "Cmd:" (unhandledCmd.Cmd.ToString ())
  out.PrintTwoCols "CmdSize:" (unhandledCmd.CmdSize.ToString ())

let dumpLoadCommands _ (file: MachBinFile) =
  file.Mach.Cmds
  |> List.iteri (fun idx cmd ->
    match cmd with
    | Mach.Segment segCmd ->
      printSegCmd segCmd idx
      file.Mach.Sections.SecByNum
      |> Array.iter (fun s ->
        if s.SegName = segCmd.SegCmdName then
          out.PrintLine ()
          out.PrintSubsubsectionTitle (String.wrapSqrdBracket "Section")
          dumpSectionDetails s.SecName file)
    | Mach.SymTab symTabCmd -> printSymTabCmd symTabCmd idx
    | Mach.DySymTab dySymTabCmd -> printDySymTabCmd dySymTabCmd idx
    | Mach.DyLib dyLibCmd -> printDyLibCmd dyLibCmd idx
    | Mach.DyLdInfo dyLdInfoCmd ->printDyLdInfoCmd dyLdInfoCmd idx
    | Mach.FuncStarts funcStartsCmd -> printFuncStartsCmd funcStartsCmd idx
    | Mach.Main mainCmd -> printMainCmd mainCmd idx
    | Mach.Unhandled unhandledCmd -> printUnhandledCmd unhandledCmd idx
    out.PrintLine ())

let dumpSharedLibs _ (file: MachBinFile) =
  let cfg = [ LeftAligned 35; LeftAligned 15; LeftAligned 15 ]
  out.PrintRow (true, cfg, [ "Lib Name"; "CurVersion"; "CompatVersion" ])
  file.Mach.Cmds
  |> List.iter (fun cmd ->
    match cmd with
    | Mach.DyLib dyLibCmd ->
      out.PrintRow (true, cfg,
        [ dyLibCmd.DyLibName
          toVersionString dyLibCmd.DyLibCurVer
          toVersionString dyLibCmd.DyLibCmpVer ])
    | _ -> ())
