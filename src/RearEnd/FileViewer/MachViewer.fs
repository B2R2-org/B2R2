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
open B2R2.RearEnd
open B2R2.RearEnd.StringUtils
open B2R2.RearEnd.FileViewer.Helper

type P = Printer

let badAccess _ _ =
  raise InvalidFileTypeException

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

let dumpFileHeader _ (fi: MachFileInfo) =
  let hdr = fi.Mach.MachHdr
  P.printTwoCols
    "Magic:"
    (u64ToHexString (uint64 hdr.Magic) + wrapParen (hdr.Magic.ToString ()))
  P.printTwoCols
    "Cpu type:"
    (hdr.CPUType.ToString ())
  P.printTwoCols
    "Cpu subtype:"
    (u32ToHexString (uint32 hdr.CPUSubType))
  P.printTwoCols
    "File type:"
    (hdr.FileType.ToString ())
  P.printTwoCols
    "Number of commands:"
    (hdr.NumCmds.ToString ())
  P.printTwoCols
    "Size of commands:"
    (hdr.SizeOfCmds.ToString ())
  P.printTwoCols
    "Flags:"
    (u64ToHexString (uint64 hdr.Flags))
  translateFlags (uint64 hdr.Flags)
  |> List.iter (fun str -> P.printTwoCols "" str)

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

let dumpSectionHeaders (opts: FileViewerOpts) (fi: MachFileInfo) =
  let addrColumn = columnWidthOfAddr fi |> LeftAligned
  if opts.Verbose then
    let cfg = [ LeftAligned 4; addrColumn; addrColumn; LeftAligned 16
                LeftAligned 8; LeftAligned 8; LeftAligned 8; LeftAligned 8
                LeftAligned 10; LeftAligned 6; LeftAligned 22
                LeftAligned 4; LeftAligned 4; LeftAligned 8 ]
    P.printrow (true, cfg, [ "Num"; "Start"; "End"; "Name"
                             "SegName"; "Size"; "Offset"; "Align"
                             "SecRelOff"; "#Reloc"; "Type"
                             "Res1"; "Res2"; "Attrib" ])
    P.println "  ---"
    fi.Mach.Sections.SecByNum
    |> Array.iteri (fun idx s ->
      P.printrow (true, cfg,
        [ wrapSqrdBracket (idx.ToString ())
          (addrToString fi.WordSize s.SecAddr)
          (addrToString fi.WordSize (s.SecAddr + s.SecSize - uint64 1))
          normalizeEmpty s.SecName
          normalizeEmpty s.SegName
          u64ToHexString s.SecSize
          u64ToHexString (uint64 s.SecOffset)
          u64ToHexString (uint64 s.SecAlignment)
          s.SecRelOff.ToString ()
          s.SecNumOfReloc.ToString ()
          s.SecType.ToString ()
          s.SecReserved1.ToString ()
          s.SecReserved2.ToString ()
          u32ToHexString (uint32 s.SecAttrib) ])
      translateAttribs (uint64 s.SecAttrib)
      |> List.iter (fun str ->
        P.printrow (true, cfg, [ ""; ""; ""; ""; ""; ""; ""; ""; ""
                                 ""; ""; ""; ""; str ]))
    )
  else
    let cfg = [ LeftAligned 4; addrColumn; addrColumn; LeftAligned 24 ]
    P.printrow (true, cfg, [ "Num"; "Start"; "End"; "Name" ])
    P.println "  ---"
    fi.GetSections ()
    |> Seq.iteri (fun idx s ->
      P.printrow (true, cfg,
        [ wrapSqrdBracket (idx.ToString ())
          (addrToString fi.WordSize s.Address)
          (addrToString fi.WordSize (s.Address + s.Size - uint64 1))
          normalizeEmpty s.Name ]))

let dumpSectionDetails (secname: string) (fi: MachFileInfo) =
  match fi.Mach.Sections.SecByName.TryFind secname with
  | Some section ->
    P.printTwoCols
      "SecName:"
      section.SecName
    P.printTwoCols
      "SegName:"
      section.SegName
    P.printTwoCols
      "SecAddr:"
      (u64ToHexString section.SecAddr)
    P.printTwoCols
      "SecSize:"
      (u64ToHexString section.SecSize)
    P.printTwoCols
      "SecOffset:"
      (u64ToHexString (uint64 section.SecOffset))
    P.printTwoCols
      "SecAlignment:"
      (u64ToHexString (uint64 section.SecAlignment))
    P.printTwoCols
      "SecRelOff:"
      (u64ToHexString (uint64 section.SecRelOff))
    P.printTwoCols
      "SecNumOfReloc:"
      (section.SecNumOfReloc.ToString ())
    P.printTwoCols
      "SecType:"
      (section.SecType.ToString ())
    P.printTwoCols
      "SecAttrib:"
      (u32ToHexString (uint32 section.SecAttrib))
    translateAttribs (uint64 section.SecAttrib)
    |> List.iter (fun str -> P.printTwoCols "" str )
    P.printTwoCols
      "SecReserved1:"
      (section.SecReserved1.ToString ())
    P.printTwoCols
      "SecReserved2:"
      (section.SecReserved2.ToString ())
  | None -> P.println "Not found."

let toVersionString (v: uint32) =
  let major = (v &&& uint32 0xFFFF0000) >>> 16
  let minor1 = (v &&& uint32 0x0000FF00) >>> 8
  let minor2 = v &&& uint32 0x000000FF
  major.ToString () + "." + minor1.ToString () + "." + minor2.ToString ()

let printSymbolInfoVerbose fi s (machSymbol: Mach.MachSymbol) cfg =
  let externLibVerinfo =
    match machSymbol.VerInfo with
    | Some info ->
      info.DyLibName
      + wrapParen
        "compatibility version " + toVersionString info.DyLibCmpVer + ", "
        + "current version" + toVersionString info.DyLibCurVer
    | None -> "(n/a)"
  P.printrow (true, cfg,
    [ targetString s
      addrToString (fi: MachFileInfo).WordSize s.Address
      normalizeEmpty s.Name
      (toLibString >> normalizeEmpty) s.LibraryName
      machSymbol.SymType.ToString ()
      machSymbol.SymDesc.ToString ()
      machSymbol.IsExternal.ToString ()
      externLibVerinfo
      wrapSqrdBracket (machSymbol.SecNum.ToString ()); ""; ""; "" ])

let printSymbolInfoNone fi s cfg =
  P.printrow (true, cfg,
    [ targetString s
      addrToString (fi: MachFileInfo).WordSize s.Address
      normalizeEmpty s.Name
      (toLibString >> normalizeEmpty) s.LibraryName
      "(n/a)"; "(n/a)"; "(n/a)"; "(n/a)"; "(n/a)" ])

let printSymbolInfo isVerbose (fi: MachFileInfo) (symbols: seq<Symbol>) =
  let addrColumn = columnWidthOfAddr fi |> LeftAligned
  if isVerbose then
    let cfg = [ LeftAligned 10; addrColumn; LeftAligned 40; LeftAligned 35
                LeftAligned 8; LeftAligned 8; LeftAligned 8; LeftAligned 8
                LeftAligned 8 ]
    P.printrow (true, cfg, [ "Kind"; "Address"; "Name"; "LibraryName"
                             "Type"; "Description"; "External"; "Version"
                             "SectionIndex" ])
    P.println "  ---"
    symbols
    |> Seq.sortBy (fun s -> s.Name)
    |> Seq.sortBy (fun s -> s.Address)
    |> Seq.sortBy (fun s -> s.Target)
    |> Seq.iter (fun s ->
      match fi.Mach.SymInfo.SymbolMap.TryFind s.Address with
      | Some machSymbol -> printSymbolInfoVerbose fi s machSymbol cfg
      | None -> printSymbolInfoNone fi s cfg)
  else
    let cfg = [ LeftAligned 10; addrColumn; LeftAligned 55; LeftAligned 15 ]
    P.printrow (true, cfg, [ "Kind"; "Address"; "Name"; "LibraryName" ])
    P.println "  ---"
    symbols
    |> Seq.sortBy (fun s -> s.Name)
    |> Seq.sortBy (fun s -> s.Address)
    |> Seq.sortBy (fun s -> s.Target)
    |> Seq.iter (fun s ->
      P.printrow (true, cfg,
        [ targetString s
          addrToString fi.WordSize s.Address
          normalizeEmpty s.Name
          (toLibString >> normalizeEmpty) s.LibraryName ]))

let dumpSymbols (opts: FileViewerOpts) (fi: MachFileInfo) =
  fi.GetSymbols ()
  |> printSymbolInfo opts.Verbose fi

let dumpRelocs (opts: FileViewerOpts) (fi: MachFileInfo) =
  fi.GetRelocationSymbols ()
  |> printSymbolInfo opts.Verbose fi

let dumpFunctions (opts: FileViewerOpts) (fi: MachFileInfo) =
  fi.GetFunctionSymbols ()
  |> printSymbolInfo opts.Verbose fi

let dumpArchiveHeader (opts: FileViewerOpts) (fi: MachFileInfo) =
  Utils.futureFeature ()

let dumpUniversalHeader (opts: FileViewerOpts) (fi: MachFileInfo) =
  Utils.futureFeature ()

let printSegCmd (segCmd: Mach.SegCmd) idx =
  P.printSubsectionTitle ("Load command " + idx.ToString ())
  P.printTwoCols "Cmd:" (segCmd.Cmd.ToString ())
  P.printTwoCols "CmdSize:" (segCmd.CmdSize.ToString ())
  P.printTwoCols "SegCmdName:" segCmd.SegCmdName
  P.printTwoCols "VMAddr:" (u64ToHexString segCmd.VMAddr)
  P.printTwoCols "VMSize:" (u64ToHexString segCmd.VMSize)
  P.printTwoCols "FileOff:" (segCmd.FileOff.ToString ())
  P.printTwoCols "FileSize:" (segCmd.FileSize.ToString ())
  P.printTwoCols "MaxProt:" (u64ToHexString (uint64 segCmd.MaxProt))
  P.printTwoCols "InitProt:" (u64ToHexString (uint64 segCmd.InitProt))
  P.printTwoCols "NumSecs:" (segCmd.NumSecs.ToString ())
  P.printTwoCols "SegFlag:" (u64ToHexString (uint64 segCmd.SegFlag))

let printSymTabCmd (symTabCmd: Mach.SymTabCmd) idx =
  P.printSubsectionTitle ("Load command " + idx.ToString ())
  P.printTwoCols "Cmd:" (symTabCmd.Cmd.ToString ())
  P.printTwoCols "CmdSize:" (symTabCmd.CmdSize.ToString ())
  P.printTwoCols "SymOff:" (u64ToHexString (uint64 symTabCmd.SymOff))
  P.printTwoCols "NumOfSym:" (symTabCmd.NumOfSym.ToString ())
  P.printTwoCols "StrOff:" (u64ToHexString (uint64 symTabCmd.StrOff))
  P.printTwoCols "StrSize:" (toNBytes (uint64 symTabCmd.StrSize))

let printDySymTabCmd (dySymTabCmd: Mach.DySymTabCmd) idx =
  P.printSubsectionTitle ("Load command " + idx.ToString ())
  P.printTwoCols "Cmd:" (dySymTabCmd.Cmd.ToString ())
  P.printTwoCols "CmdSize:" (dySymTabCmd.CmdSize.ToString ())
  P.printTwoCols "IdxLocalSym:" (dySymTabCmd.IdxLocalSym.ToString ())
  P.printTwoCols "NumLocalSym:" (dySymTabCmd.NumLocalSym.ToString ())
  P.printTwoCols "IdxExtSym:" (dySymTabCmd.IdxExtSym.ToString ())
  P.printTwoCols "NumExtSym:" (dySymTabCmd.NumExtSym.ToString ())
  P.printTwoCols "IdxUndefSym:" (dySymTabCmd.IdxUndefSym.ToString ())
  P.printTwoCols "NumUndefSym:" (dySymTabCmd.NumUndefSym.ToString ())
  P.printTwoCols "TOCOffset:" (dySymTabCmd.TOCOffset.ToString ())
  P.printTwoCols "NumTOCContents:" (dySymTabCmd.NumTOCContents.ToString ())
  P.printTwoCols "ModTabOff:" (dySymTabCmd.ModTabOff.ToString ())
  P.printTwoCols "NumModTab:" (dySymTabCmd.NumModTab.ToString ())
  P.printTwoCols "ExtRefSymOff:" (dySymTabCmd.ExtRefSymOff.ToString ())
  P.printTwoCols "NumExtRefSym:" (dySymTabCmd.NumExtRefSym.ToString ())
  P.printTwoCols "IndirectSymOff:" (dySymTabCmd.IndirectSymOff.ToString ())
  P.printTwoCols "NumIndirectSym:" (dySymTabCmd.NumIndirectSym.ToString ())
  P.printTwoCols "ExtRelOff:" (dySymTabCmd.ExtRelOff.ToString ())
  P.printTwoCols "NumExtRel:" (dySymTabCmd.NumExtRel.ToString ())
  P.printTwoCols "LocalRelOff:" (dySymTabCmd.LocalRelOff.ToString ())
  P.printTwoCols "NumLocalRel:" (dySymTabCmd.NumLocalRel.ToString ())

let toTimeStampString (v: uint32) =
  ((DateTime.UnixEpoch.AddSeconds (float v)).ToLocalTime ()).ToString ()
  + TimeZoneInfo.Local.ToString ()

let printDyLibCmd (dyLibCmd: Mach.DyLibCmd) idx =
  P.printSubsectionTitle ("Load command " + idx.ToString ())
  P.printTwoCols "Cmd:" (dyLibCmd.Cmd.ToString ())
  P.printTwoCols "CmdSize:" (dyLibCmd.CmdSize.ToString ())
  P.printTwoCols "DyLibName:" dyLibCmd.DyLibName
  P.printTwoCols "DyLibTimeStamp:" (toTimeStampString dyLibCmd.DyLibTimeStamp)
  P.printTwoCols "DyLibCurVer:" (toVersionString dyLibCmd.DyLibCurVer)
  P.printTwoCols "DyLibCmpVer:" (toVersionString dyLibCmd.DyLibCmpVer)

let printDyLdInfoCmd (dyLdInfoCmd: Mach.DyLdInfoCmd) idx =
  P.printSubsectionTitle ("Load command " + idx.ToString ())
  P.printTwoCols "Cmd:" (dyLdInfoCmd.Cmd.ToString ())
  P.printTwoCols "CmdSize:" (dyLdInfoCmd.CmdSize.ToString ())
  P.printTwoCols "RebaseOff:" (dyLdInfoCmd.RebaseOff.ToString ())
  P.printTwoCols "RebaseSize:" (dyLdInfoCmd.RebaseSize.ToString ())
  P.printTwoCols "BindOff:" (dyLdInfoCmd.BindOff.ToString ())
  P.printTwoCols "BindSize:" (dyLdInfoCmd.BindSize.ToString ())
  P.printTwoCols "WeakBindOff:" (dyLdInfoCmd.WeakBindOff.ToString ())
  P.printTwoCols "WeakBindSize:" (dyLdInfoCmd.WeakBindSize.ToString ())
  P.printTwoCols "LazyBindOff:" (dyLdInfoCmd.LazyBindOff.ToString ())
  P.printTwoCols "LazyBindSize:" (dyLdInfoCmd.LazyBindSize.ToString ())
  P.printTwoCols "ExportOff:" (dyLdInfoCmd.ExportOff.ToString ())
  P.printTwoCols "ExportSize:" (dyLdInfoCmd.ExportSize.ToString ())

let printFuncStartsCmd (funcStartsCmd: Mach.FuncStartsCmd) idx =
  P.printSubsectionTitle ("Load command " + idx.ToString ())
  P.printTwoCols "DataOffset:" (funcStartsCmd.DataOffset.ToString ())
  P.printTwoCols "DataSize:" (funcStartsCmd.DataSize.ToString ())

let printMainCmd (mainCmd: Mach.MainCmd) idx =
  P.printSubsectionTitle ("Load command " + idx.ToString ())
  P.printTwoCols "Cmd:" (mainCmd.Cmd.ToString ())
  P.printTwoCols "CmdSize:" (mainCmd.CmdSize.ToString ())
  P.printTwoCols "EntryOff:" (mainCmd.EntryOff.ToString ())
  P.printTwoCols "StackSize:" (mainCmd.StackSize.ToString ())

let printUnhandledCmd (unhandledCmd: Mach.UnhandledCommand) idx =
  P.printSubsectionTitle ("Load command " + idx.ToString ())
  P.printTwoCols "Cmd:" (unhandledCmd.Cmd.ToString ())
  P.printTwoCols "CmdSize:" (unhandledCmd.CmdSize.ToString ())

let dumpLoadCommands _ (fi: MachFileInfo) =
  fi.Mach.Cmds
  |> List.iteri (fun idx cmd ->
    match cmd with
    | Mach.Segment segCmd ->
      printSegCmd segCmd idx
      fi.Mach.Sections.SecByNum
      |> Array.iter (fun s ->
        if s.SegName = segCmd.SegCmdName then
          P.println ()
          P.printSubsubsectionTitle (wrapSqrdBracket "Section")
          dumpSectionDetails s.SecName fi)
    | Mach.SymTab symTabCmd -> printSymTabCmd symTabCmd idx
    | Mach.DySymTab dySymTabCmd -> printDySymTabCmd dySymTabCmd idx
    | Mach.DyLib dyLibCmd -> printDyLibCmd dyLibCmd idx
    | Mach.DyLdInfo dyLdInfoCmd ->printDyLdInfoCmd dyLdInfoCmd idx
    | Mach.FuncStarts funcStartsCmd -> printFuncStartsCmd funcStartsCmd idx
    | Mach.Main mainCmd -> printMainCmd mainCmd idx
    | Mach.Unhandled unhandledCmd -> printUnhandledCmd unhandledCmd idx
    P.println ())

let dumpSharedLibs _ (fi: MachFileInfo) =
  let cfg = [ LeftAligned 35; LeftAligned 15; LeftAligned 15 ]
  P.printrow (true, cfg, [ "LibraryName"; "CurVersion"; "CompatVersion" ])
  fi.Mach.Cmds
  |> List.iter (fun cmd ->
    match cmd with
    | Mach.DyLib dyLibCmd ->
      P.printrow (true, cfg,
        [ dyLibCmd.DyLibName
          toVersionString dyLibCmd.DyLibCurVer
          toVersionString dyLibCmd.DyLibCmpVer ])
    | _ -> ())
