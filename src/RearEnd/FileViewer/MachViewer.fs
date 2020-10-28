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
open B2R2.RearEnd.FileViewer.Helper

let badAccess _ _ =
  raise InvalidFileTypeException

let translateFlags flags =
  let enumFlags =
    System.Enum.GetValues (typeof<Mach.MachFlag>)
    :?> Mach.MachFlag []
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
  printTwoCols
    "Magic:"
    (toHexString (uint64 hdr.Magic) + wrapParen (hdr.Magic.ToString ()))
  printTwoCols
    "Cpu type:"
    (hdr.CPUType.ToString ())
  printTwoCols
    "Cpu subtype:"
    (toHexString32 (uint32 hdr.CPUSubType))
  printTwoCols
    "File type:"
    (hdr.FileType.ToString ())
  printTwoCols
    "Number of commands:"
    (hdr.NumCmds.ToString ())
  printTwoCols
    "Size of commands:"
    (hdr.SizeOfCmds.ToString ())
  printTwoCols
    "Flags:"
    (toHexString (uint64 hdr.Flags))
  translateFlags (uint64 hdr.Flags)
  |> List.iter (fun str -> printTwoCols "" str)

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
    Printer.printrow true cfg [ "Num"; "Start"; "End"; "Name"
                                "SegName"; "Size"; "Offset"; "Align"
                                "SecRelOff"; "#Reloc"; "Type"
                                "Res1"; "Res2"; "Attrib" ]
    Printer.println "  ---"
    fi.Mach.Sections.SecByNum
    |> Array.iteri (fun idx s ->
      Printer.printrow true cfg
        [ wrapSqrdBrac (idx.ToString ())
          (addrToString fi.WordSize s.SecAddr)
          (addrToString fi.WordSize (s.SecAddr + s.SecSize - uint64 1))
          normalizeEmpty s.SecName
          normalizeEmpty s.SegName
          toHexString s.SecSize
          toHexString (uint64 s.SecOffset)
          toHexString (uint64 s.SecAlignment)
          s.SecRelOff.ToString ()
          s.SecNumOfReloc.ToString ()
          s.SecType.ToString ()
          s.SecReserved1.ToString ()
          s.SecReserved2.ToString ()
          toHexString32 (uint32 s.SecAttrib) ]
      translateAttribs (uint64 s.SecAttrib)
      |> List.iter (fun str ->
        Printer.printrow true cfg [ ""; ""; ""; ""; ""; ""; ""; ""; ""
                                    ""; ""; ""; ""; str ])
          )
  else
    let cfg = [ LeftAligned 4; addrColumn; addrColumn; LeftAligned 24 ]
    Printer.printrow true cfg [ "Num"; "Start"; "End"; "Name" ]
    Printer.println "  ---"
    fi.GetSections ()
    |> Seq.iteri (fun idx s ->
      Printer.printrow true cfg
        [ wrapSqrdBrac (idx.ToString ())
          (addrToString fi.WordSize s.Address)
          (addrToString fi.WordSize (s.Address + s.Size - uint64 1))
          normalizeEmpty s.Name ])

let dumpSectionDetails (secname: string) (fi: MachFileInfo) =
  match fi.Mach.Sections.SecByName.TryFind secname with
  | Some section ->
    printTwoCols
      "SecName:"
      section.SecName
    printTwoCols
      "SegName:"
      section.SegName
    printTwoCols
      "SecAddr:"
      (toHexString section.SecAddr)
    printTwoCols
      "SecSize:"
      (toHexString section.SecSize)
    printTwoCols
      "SecOffset:"
      (toHexString (uint64 section.SecOffset))
    printTwoCols
      "SecAlignment:"
      (toHexString (uint64 section.SecAlignment))
    printTwoCols
      "SecRelOff:"
      (toHexString (uint64 section.SecRelOff))
    printTwoCols
      "SecNumOfReloc:"
      (section.SecNumOfReloc.ToString ())
    printTwoCols
      "SecType:"
      (section.SecType.ToString ())
    printTwoCols
      "SecAttrib:"
      (toHexString32 (uint32 section.SecAttrib))
    translateAttribs (uint64 section.SecAttrib)
    |> List.iter (fun str -> printTwoCols "" str )
    printTwoCols
      "SecReserved1:"
      (section.SecReserved1.ToString ())
    printTwoCols
      "SecReserved2:"
      (section.SecReserved2.ToString ())
  | None -> Printer.println "Not found."

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
  Printer.printrow true cfg
    [ targetString s
      addrToString (fi: MachFileInfo).WordSize s.Address
      normalizeEmpty s.Name
      (toLibString >> normalizeEmpty) s.LibraryName
      machSymbol.SymType.ToString ()
      machSymbol.SymDesc.ToString ()
      machSymbol.IsExternal.ToString ()
      externLibVerinfo
      wrapSqrdBrac (machSymbol.SecNum.ToString ()); ""; ""; "" ]

let printSymbolInfoNone fi s cfg =
  Printer.printrow true cfg
    [ targetString s
      addrToString (fi: MachFileInfo).WordSize s.Address
      normalizeEmpty s.Name
      (toLibString >> normalizeEmpty) s.LibraryName
      "(n/a)"; "(n/a)"; "(n/a)"; "(n/a)"; "(n/a)" ]

let printSymbolInfo isVerbose (fi: MachFileInfo) (symbols: seq<Symbol>) =
  let addrColumn = columnWidthOfAddr fi |> LeftAligned
  if isVerbose then
    let cfg = [ LeftAligned 10; addrColumn; LeftAligned 40; LeftAligned 35
                LeftAligned 8; LeftAligned 8; LeftAligned 8; LeftAligned 8
                LeftAligned 8 ]
    Printer.printrow true cfg [ "Kind"; "Address"; "Name"; "LibraryName"
                                "Type"; "Description"; "External"; "Version"
                                "SectionIndex" ]
    Printer.println "  ---"
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
    Printer.printrow true cfg [ "Kind"; "Address"; "Name"; "LibraryName" ]
    Printer.println "  ---"
    symbols
    |> Seq.sortBy (fun s -> s.Name)
    |> Seq.sortBy (fun s -> s.Address)
    |> Seq.sortBy (fun s -> s.Target)
    |> Seq.iter (fun s ->
      Printer.printrow true cfg
        [ targetString s
          addrToString fi.WordSize s.Address
          normalizeEmpty s.Name
          (toLibString >> normalizeEmpty) s.LibraryName ])

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
  printSubsectionTitle ("Load command " + idx.ToString ())
  printTwoCols "Cmd:" (segCmd.Cmd.ToString ())
  printTwoCols "CmdSize:" (segCmd.CmdSize.ToString ())
  printTwoCols "SegCmdName:" segCmd.SegCmdName
  printTwoCols "VMAddr:" (toHexString segCmd.VMAddr)
  printTwoCols "VMSize:" (toHexString segCmd.VMSize)
  printTwoCols "FileOff:" (segCmd.FileOff.ToString ())
  printTwoCols "FileSize:" (segCmd.FileSize.ToString ())
  printTwoCols "MaxProt:" (toHexString (uint64 segCmd.MaxProt))
  printTwoCols "InitProt:" (toHexString (uint64 segCmd.InitProt))
  printTwoCols "NumSecs:" (segCmd.NumSecs.ToString ())
  printTwoCols "SegFlag:" (toHexString (uint64 segCmd.SegFlag))

let printSymTabCmd (symTabCmd: Mach.SymTabCmd) idx =
  printSubsectionTitle ("Load command " + idx.ToString ())
  printTwoCols "Cmd:" (symTabCmd.Cmd.ToString ())
  printTwoCols "CmdSize:" (symTabCmd.CmdSize.ToString ())
  printTwoCols "SymOff:" (toHexString (uint64 symTabCmd.SymOff))
  printTwoCols "NumOfSym:" (symTabCmd.NumOfSym.ToString ())
  printTwoCols "StrOff:" (toHexString (uint64 symTabCmd.StrOff))
  printTwoCols "StrSize:" (toNBytes (uint64 symTabCmd.StrSize))

let printDySymTabCmd (dySymTabCmd: Mach.DySymTabCmd) idx =
  printSubsectionTitle ("Load command " + idx.ToString ())
  printTwoCols "Cmd:" (dySymTabCmd.Cmd.ToString ())
  printTwoCols "CmdSize:" (dySymTabCmd.CmdSize.ToString ())
  printTwoCols "IdxLocalSym:" (dySymTabCmd.IdxLocalSym.ToString ())
  printTwoCols "NumLocalSym:" (dySymTabCmd.NumLocalSym.ToString ())
  printTwoCols "IdxExtSym:" (dySymTabCmd.IdxExtSym.ToString ())
  printTwoCols "NumExtSym:" (dySymTabCmd.NumExtSym.ToString ())
  printTwoCols "IdxUndefSym:" (dySymTabCmd.IdxUndefSym.ToString ())
  printTwoCols "NumUndefSym:" (dySymTabCmd.NumUndefSym.ToString ())
  printTwoCols "TOCOffset:" (dySymTabCmd.TOCOffset.ToString ())
  printTwoCols "NumTOCContents:" (dySymTabCmd.NumTOCContents.ToString ())
  printTwoCols "ModTabOff:" (dySymTabCmd.ModTabOff.ToString ())
  printTwoCols "NumModTab:" (dySymTabCmd.NumModTab.ToString ())
  printTwoCols "ExtRefSymOff:" (dySymTabCmd.ExtRefSymOff.ToString ())
  printTwoCols "NumExtRefSym:" (dySymTabCmd.NumExtRefSym.ToString ())
  printTwoCols "IndirectSymOff:" (dySymTabCmd.IndirectSymOff.ToString ())
  printTwoCols "NumIndirectSym:" (dySymTabCmd.NumIndirectSym.ToString ())
  printTwoCols "ExtRelOff:" (dySymTabCmd.ExtRelOff.ToString ())
  printTwoCols "NumExtRel:" (dySymTabCmd.NumExtRel.ToString ())
  printTwoCols "LocalRelOff:" (dySymTabCmd.LocalRelOff.ToString ())
  printTwoCols "NumLocalRel:" (dySymTabCmd.NumLocalRel.ToString ())

let toTimeStampString (v: uint32) =
  ((DateTime.UnixEpoch.AddSeconds (float v)).ToLocalTime ()).ToString ()
  + TimeZoneInfo.Local.ToString ()

let printDyLibCmd (dyLibCmd: Mach.DyLibCmd) idx =
  printSubsectionTitle ("Load command " + idx.ToString ())
  printTwoCols "Cmd:" (dyLibCmd.Cmd.ToString ())
  printTwoCols "CmdSize:" (dyLibCmd.CmdSize.ToString ())
  printTwoCols "DyLibName:" dyLibCmd.DyLibName
  printTwoCols "DyLibTimeStamp:" (toTimeStampString dyLibCmd.DyLibTimeStamp)
  printTwoCols "DyLibCurVer:" (toVersionString dyLibCmd.DyLibCurVer)
  printTwoCols "DyLibCmpVer:" (toVersionString dyLibCmd.DyLibCmpVer)

let printDyLdInfoCmd (dyLdInfoCmd: Mach.DyLdInfoCmd) idx =
  printSubsectionTitle ("Load command " + idx.ToString ())
  printTwoCols "Cmd:" (dyLdInfoCmd.Cmd.ToString ())
  printTwoCols "CmdSize:" (dyLdInfoCmd.CmdSize.ToString ())
  printTwoCols "RebaseOff:" (dyLdInfoCmd.RebaseOff.ToString ())
  printTwoCols "RebaseSize:" (dyLdInfoCmd.RebaseSize.ToString ())
  printTwoCols "BindOff:" (dyLdInfoCmd.BindOff.ToString ())
  printTwoCols "BindSize:" (dyLdInfoCmd.BindSize.ToString ())
  printTwoCols "WeakBindOff:" (dyLdInfoCmd.WeakBindOff.ToString ())
  printTwoCols "WeakBindSize:" (dyLdInfoCmd.WeakBindSize.ToString ())
  printTwoCols "LazyBindOff:" (dyLdInfoCmd.LazyBindOff.ToString ())
  printTwoCols "LazyBindSize:" (dyLdInfoCmd.LazyBindSize.ToString ())
  printTwoCols "ExportOff:" (dyLdInfoCmd.ExportOff.ToString ())
  printTwoCols "ExportSize:" (dyLdInfoCmd.ExportSize.ToString ())

let printFuncStartsCmd (funcStartsCmd: Mach.FuncStartsCmd) idx =
  printSubsectionTitle ("Load command " + idx.ToString ())
  printTwoCols "DataOffset:" (funcStartsCmd.DataOffset.ToString ())
  printTwoCols "DataSize:" (funcStartsCmd.DataSize.ToString ())

let printMainCmd (mainCmd: Mach.MainCmd) idx =
  printSubsectionTitle ("Load command " + idx.ToString ())
  printTwoCols "Cmd:" (mainCmd.Cmd.ToString ())
  printTwoCols "CmdSize:" (mainCmd.CmdSize.ToString ())
  printTwoCols "EntryOff:" (mainCmd.EntryOff.ToString ())
  printTwoCols "StackSize:" (mainCmd.StackSize.ToString ())

let printUnhandledCmd (unhandledCmd: Mach.UnhandledCommand) idx =
  printSubsectionTitle ("Load command " + idx.ToString ())
  printTwoCols "Cmd:" (unhandledCmd.Cmd.ToString ())
  printTwoCols "CmdSize:" (unhandledCmd.CmdSize.ToString ())

let dumpLoadCommands _ (fi: MachFileInfo) =
  fi.Mach.Cmds
  |> List.iteri (fun idx cmd ->
    match cmd with
    | Mach.Segment segCmd ->
      printSegCmd segCmd idx
      fi.Mach.Sections.SecByNum
      |> Array.iter (fun s ->
        if s.SegName = segCmd.SegCmdName then
          Printer.println ()
          printSubsubsectionTitle (wrapSqrdBrac "Section")
          dumpSectionDetails s.SecName fi)
    | Mach.SymTab symTabCmd -> printSymTabCmd symTabCmd idx
    | Mach.DySymTab dySymTabCmd -> printDySymTabCmd dySymTabCmd idx
    | Mach.DyLib dyLibCmd -> printDyLibCmd dyLibCmd idx
    | Mach.DyLdInfo dyLdInfoCmd ->printDyLdInfoCmd dyLdInfoCmd idx
    | Mach.FuncStarts funcStartsCmd -> printFuncStartsCmd funcStartsCmd idx
    | Mach.Main mainCmd -> printMainCmd mainCmd idx
    | Mach.Unhandled unhandledCmd -> printUnhandledCmd unhandledCmd idx
    Printer.println ())

let dumpSharedLibs _ (fi: MachFileInfo) =
  let cfg = [ LeftAligned 35; LeftAligned 15; LeftAligned 15 ]
  Printer.printrow true cfg [ "LibraryName"; "CurVersion"; "CompatVersion" ]
  fi.Mach.Cmds
  |> List.iter (fun cmd ->
    match cmd with
    | Mach.DyLib dyLibCmd ->
      Printer.printrow true cfg
        [ dyLibCmd.DyLibName
          toVersionString dyLibCmd.DyLibCurVer
          toVersionString dyLibCmd.DyLibCmpVer ]
    | _ -> ())
