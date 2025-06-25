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
open B2R2.RearEnd.Utils

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
  let hdr = file.Header
  out.PrintTwoCols
    "Magic:"
    (HexString.ofUInt64 (uint64 hdr.Magic)
    + String.wrapParen (hdr.Magic.ToString ()))
  out.PrintTwoCols
    "Cpu type:"
    (hdr.CPUType.ToString ())
  out.PrintTwoCols
    "Cpu subtype:"
    (HexString.ofInt32 (int hdr.CPUSubType))
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
    (HexString.ofUInt64 (uint64 hdr.Flags))
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

let dumpSectionHeaders (opts: FileViewerOpts) (mach: MachBinFile) =
  let addrColumn = columnWidthOfAddr mach |> LeftAligned
  let file = mach :> IBinFile
  if opts.Verbose then
    let cfg =
      [ LeftAligned 4
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
        LeftAligned 8 ]
    out.PrintRow (true, cfg,
      [ "Num"
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
        "Attrib" ])
    out.PrintLine "  ---"
    mach.Sections
    |> Array.iteri (fun idx s ->
      out.PrintRow (true, cfg,
        [ String.wrapSqrdBracket (idx.ToString ())
          (Addr.toString file.ISA.WordSize s.SecAddr)
          (Addr.toString file.ISA.WordSize (s.SecAddr + s.SecSize - uint64 1))
          normalizeEmpty s.SecName
          normalizeEmpty s.SegName
          HexString.ofUInt64 s.SecSize
          HexString.ofUInt64 (uint64 s.SecOffset)
          HexString.ofUInt64 (uint64 s.SecAlignment)
          s.SecRelOff.ToString ()
          s.SecNumOfReloc.ToString ()
          s.SecType.ToString ()
          s.SecReserved1.ToString ()
          s.SecReserved2.ToString ()
          HexString.ofUInt32 (uint32 s.SecAttrib) ])
      translateAttribs (uint64 s.SecAttrib)
      |> List.iter (fun str ->
        out.PrintRow (true, cfg,
          [ ""; ""; ""; ""; ""; ""; ""; ""; ""; ""; ""; ""; ""; str ]))
    )
  else
    let cfg = [ LeftAligned 4; addrColumn; addrColumn; LeftAligned 24 ]
    out.PrintRow (true, cfg, [ "Num"; "Start"; "End"; "Name" ])
    out.PrintLine "  ---"
    mach.Sections
    |> Array.iteri (fun idx s ->
      out.PrintRow (true, cfg,
        [ String.wrapSqrdBracket (idx.ToString ())
          (Addr.toString file.ISA.WordSize s.SecAddr)
          (Addr.toString file.ISA.WordSize (s.SecAddr + uint64 s.SecSize - 1UL))
          normalizeEmpty s.SecName ]))

let dumpSectionDetails (secName: string) (file: MachBinFile) =
  match file.Sections |> Array.tryFind (fun s -> s.SecName = secName) with
  | Some section ->
    out.PrintTwoCols
      "SecName:"
      section.SecName
    out.PrintTwoCols
      "SegName:"
      section.SegName
    out.PrintTwoCols
      "SecAddr:"
      (HexString.ofUInt64 section.SecAddr)
    out.PrintTwoCols
      "SecSize:"
      (HexString.ofUInt64 section.SecSize)
    out.PrintTwoCols
      "SecOffset:"
      (HexString.ofUInt64 (uint64 section.SecOffset))
    out.PrintTwoCols
      "SecAlignment:"
      (HexString.ofUInt64 (uint64 section.SecAlignment))
    out.PrintTwoCols
      "SecRelOff:"
      (HexString.ofUInt64 (uint64 section.SecRelOff))
    out.PrintTwoCols
      "SecNumOfReloc:"
      (section.SecNumOfReloc.ToString ())
    out.PrintTwoCols
      "SecType:"
      (section.SecType.ToString ())
    out.PrintTwoCols
      "SecAttrib:"
      (HexString.ofInt32 (int section.SecAttrib))
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

let printSymbolInfoVerbose file (symb: Mach.Symbol) vis cfg =
  out.PrintRow (true, cfg,
    [ vis
      Addr.toString (file: IBinFile).ISA.WordSize symb.SymAddr
      normalizeEmpty symb.SymName
      getSymbolLibName symb
      symb.SymType.ToString ()
      symb.SymDesc.ToString ()
      symb.IsExternal.ToString ()
      getLibName symb
      String.wrapSqrdBracket (symb.SecNum.ToString ())
      ""
      ""
      "" ])


let printSymbolInfoNonVerbose mach (symb: Mach.Symbol) vis cfg =
  out.PrintRow (true, cfg,
    [ vis
      $"{symb.SymType}"
      Addr.toString (mach :> IBinFile).ISA.WordSize symb.SymAddr
      normalizeEmpty symb.SymName
      getLibName symb ])

let printSymbolInfo isVerbose (mach: MachBinFile) =
  let addrColumn = columnWidthOfAddr mach |> LeftAligned
  if isVerbose then
    let cfg =
      [ LeftAligned 3
        addrColumn
        LeftAligned 40
        LeftAligned 35
        LeftAligned 8
        LeftAligned 8
        LeftAligned 8
        LeftAligned 8
        LeftAligned 8 ]
    out.PrintRow (true, cfg,
      [ "S/D"
        "Address"
        "Name"
        "Lib Name"
        "Type"
        "Description"
        "External"
        "Version"
        "SectionIndex" ])
    out.PrintLine "  ---"
    mach.StaticSymbols
    |> Array.sortBy (fun s -> s.SymName)
    |> Array.sortBy (fun s -> s.SymAddr)
    |> Array.iter (fun s -> printSymbolInfoVerbose mach s "(s)" cfg)
    mach.DynamicSymbols
    |> Array.sortBy (fun s -> s.SymName)
    |> Array.sortBy (fun s -> s.SymAddr)
    |> Array.iter (fun s -> printSymbolInfoVerbose mach s "(d)" cfg)
  else
    let cfg =
      [ LeftAligned 3
        LeftAligned 10
        addrColumn
        LeftAligned 55
        LeftAligned 15 ]
    out.PrintRow (true, cfg, [ "S/D"; "Kind"; "Address"; "Name"; "Lib Name" ])
    out.PrintLine "  ---"
    mach.StaticSymbols
    |> Array.sortBy (fun s -> s.SymName)
    |> Array.sortBy (fun s -> s.SymAddr)
    |> Array.iter (fun s -> printSymbolInfoNonVerbose mach s "(s)" cfg)
    mach.DynamicSymbols
    |> Array.sortBy (fun s -> s.SymName)
    |> Array.sortBy (fun s -> s.SymAddr)
    |> Array.iter (fun s -> printSymbolInfoNonVerbose mach s "(d)" cfg)

let dumpSymbols (opts: FileViewerOpts) (mach: MachBinFile) =
  printSymbolInfo opts.Verbose mach

let dumpRelocs (_: FileViewerOpts) (mach: MachBinFile) =
  let addrColumn = columnWidthOfAddr mach |> LeftAligned
  let cfg = [ addrColumn; LeftAligned 55; LeftAligned 15 ]
  out.PrintRow (true, cfg, [ "Address"; "Name"; "Length" ])
  for reloc in mach.Relocations do
    let addr = reloc.RelocSection.SecAddr + uint64 reloc.RelocAddr
    let name = reloc.GetName (mach.Symbols.Values, mach.Sections)
    let len = reloc.RelocAddr
    out.PrintRow (true, cfg,
      [ Addr.toString (mach :> IBinFile).ISA.WordSize addr
        name
        $"{len}" ])

let dumpFunctions (opts: FileViewerOpts) (mach: MachBinFile) =
  let addrColumn = columnWidthOfAddr mach |> LeftAligned
  let cfg =
    [ LeftAligned 3
      LeftAligned 10
      addrColumn
      LeftAligned 55
      LeftAligned 15 ]
  for addr in (mach :> IBinFile).GetFunctionAddresses () do
    match mach.Symbols.SymbolMap.TryFind addr with
    | Some symb -> printSymbolInfoNonVerbose mach symb "" cfg
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
      out.PrintSubsectionTitle ("Architecture #" + idx.ToString ())
      out.PrintTwoCols "CPU Type:" (cpu.ToString ())
      out.PrintTwoCols "CPU Subtype:" ("0x" + (uint32 cpusub).ToString ("x"))
      out.PrintTwoCols "Offset:" ("0x" + fat.Offset.ToString ("x"))
      out.PrintTwoCols "Size:" (fat.Size.ToString ())
    )
  else printfn "Not a FAT binary."

let printSegCmd cmd size (seg: Mach.SegCmd) idx =
  out.PrintSubsectionTitle ("Load command " + idx.ToString ())
  out.PrintTwoCols "Cmd:" (cmd.ToString ())
  out.PrintTwoCols "CmdSize:" (size.ToString ())
  out.PrintTwoCols "SegCmdName:" seg.SegCmdName
  out.PrintTwoCols "VMAddr:" (HexString.ofUInt64 seg.VMAddr)
  out.PrintTwoCols "VMSize:" (HexString.ofUInt64 seg.VMSize)
  out.PrintTwoCols "FileOff:" (seg.FileOff.ToString ())
  out.PrintTwoCols "FileSize:" (seg.FileSize.ToString ())
  out.PrintTwoCols "MaxProt:" (HexString.ofUInt64 (uint64 seg.MaxProt))
  out.PrintTwoCols "InitProt:" (HexString.ofUInt64 (uint64 seg.InitProt))
  out.PrintTwoCols "NumSecs:" (seg.NumSecs.ToString ())
  out.PrintTwoCols "SegFlag:" (HexString.ofUInt64 (uint64 seg.SegFlag))

let printSymTabCmd cmd size (symtab: Mach.SymTabCmd) idx =
  out.PrintSubsectionTitle ("Load command " + idx.ToString ())
  out.PrintTwoCols "Cmd:" (cmd.ToString ())
  out.PrintTwoCols "CmdSize:" (size.ToString ())
  out.PrintTwoCols "SymOff:" (HexString.ofUInt64 (uint64 symtab.SymOff))
  out.PrintTwoCols "NumOfSym:" (symtab.NumOfSym.ToString ())
  out.PrintTwoCols "StrOff:" (HexString.ofUInt64 (uint64 symtab.StrOff))
  out.PrintTwoCols "StrSize:" (toNBytes (uint64 symtab.StrSize))

let printDySymTabCmd cmd size (dysymtab: Mach.DySymTabCmd) idx =
  out.PrintSubsectionTitle ("Load command " + idx.ToString ())
  out.PrintTwoCols "Cmd:" (cmd.ToString ())
  out.PrintTwoCols "CmdSize:" (size.ToString ())
  out.PrintTwoCols "IdxLocalSym:" (dysymtab.IdxLocalSym.ToString ())
  out.PrintTwoCols "NumLocalSym:" (dysymtab.NumLocalSym.ToString ())
  out.PrintTwoCols "IdxExtSym:" (dysymtab.IdxExtSym.ToString ())
  out.PrintTwoCols "NumExtSym:" (dysymtab.NumExtSym.ToString ())
  out.PrintTwoCols "IdxUndefSym:" (dysymtab.IdxUndefSym.ToString ())
  out.PrintTwoCols "NumUndefSym:" (dysymtab.NumUndefSym.ToString ())
  out.PrintTwoCols "TOCOffset:" (dysymtab.TOCOffset.ToString ())
  out.PrintTwoCols "NumTOCContents:" (dysymtab.NumTOCContents.ToString ())
  out.PrintTwoCols "ModTabOff:" (dysymtab.ModTabOff.ToString ())
  out.PrintTwoCols "NumModTab:" (dysymtab.NumModTab.ToString ())
  out.PrintTwoCols "ExtRefSymOff:" (dysymtab.ExtRefSymOff.ToString ())
  out.PrintTwoCols "NumExtRefSym:" (dysymtab.NumExtRefSym.ToString ())
  out.PrintTwoCols "IndirectSymOff:" (dysymtab.IndirectSymOff.ToString ())
  out.PrintTwoCols "NumIndirectSym:" (dysymtab.NumIndirectSym.ToString ())
  out.PrintTwoCols "ExtRelOff:" (dysymtab.ExtRelOff.ToString ())
  out.PrintTwoCols "NumExtRel:" (dysymtab.NumExtRel.ToString ())
  out.PrintTwoCols "LocalRelOff:" (dysymtab.LocalRelOff.ToString ())
  out.PrintTwoCols "NumLocalRel:" (dysymtab.NumLocalRel.ToString ())

let toTimeStampString (v: uint32) =
  ((DateTime.UnixEpoch.AddSeconds (float v)).ToLocalTime ()).ToString ()
  + TimeZoneInfo.Local.ToString ()

let printDyLibCmd cmd size (dylib: Mach.DyLibCmd) idx =
  out.PrintSubsectionTitle ("Load command " + idx.ToString ())
  out.PrintTwoCols "Cmd:" (cmd.ToString ())
  out.PrintTwoCols "CmdSize:" (size.ToString ())
  out.PrintTwoCols "DyLibName:" dylib.DyLibName
  out.PrintTwoCols "DyLibTimeStamp:" (toTimeStampString dylib.DyLibTimeStamp)
  out.PrintTwoCols "DyLibCurVer:" (toVersionString dylib.DyLibCurVer)
  out.PrintTwoCols "DyLibCmpVer:" (toVersionString dylib.DyLibCmpVer)

let printDyLdInfoCmd cmd size (ldinfo: Mach.DyLdInfoCmd) idx =
  out.PrintSubsectionTitle ("Load command " + idx.ToString ())
  out.PrintTwoCols "Cmd:" (cmd.ToString ())
  out.PrintTwoCols "CmdSize:" (size.ToString ())
  out.PrintTwoCols "RebaseOff:" (ldinfo.RebaseOff.ToString ())
  out.PrintTwoCols "RebaseSize:" (ldinfo.RebaseSize.ToString ())
  out.PrintTwoCols "BindOff:" (ldinfo.BindOff.ToString ())
  out.PrintTwoCols "BindSize:" (ldinfo.BindSize.ToString ())
  out.PrintTwoCols "WeakBindOff:" (ldinfo.WeakBindOff.ToString ())
  out.PrintTwoCols "WeakBindSize:" (ldinfo.WeakBindSize.ToString ())
  out.PrintTwoCols "LazyBindOff:" (ldinfo.LazyBindOff.ToString ())
  out.PrintTwoCols "LazyBindSize:" (ldinfo.LazyBindSize.ToString ())
  out.PrintTwoCols "ExportOff:" (ldinfo.ExportOff.ToString ())
  out.PrintTwoCols "ExportSize:" (ldinfo.ExportSize.ToString ())

let printFuncStartsCmd (fnstart: Mach.FuncStartsCmd) idx =
  out.PrintSubsectionTitle ("Load command " + idx.ToString ())
  out.PrintTwoCols "DataOffset:" (fnstart.DataOffset.ToString ())
  out.PrintTwoCols "DataSize:" (fnstart.DataSize.ToString ())

let printMainCmd cmd size (main: Mach.MainCmd) idx =
  out.PrintSubsectionTitle ("Load command " + idx.ToString ())
  out.PrintTwoCols "Cmd:" (cmd.ToString ())
  out.PrintTwoCols "CmdSize:" (size.ToString ())
  out.PrintTwoCols "EntryOff:" (main.EntryOff.ToString ())
  out.PrintTwoCols "StackSize:" (main.StackSize.ToString ())

let printUnhandledCmd cmd size idx =
  out.PrintSubsectionTitle ("Load command " + idx.ToString ())
  out.PrintTwoCols "Cmd:" (cmd.ToString ())
  out.PrintTwoCols "CmdSize:" (size.ToString ())

let dumpLoadCommands _ (file: MachBinFile) =
  file.Commands
  |> Array.iteri (fun idx cmd ->
    match cmd with
    | Mach.Segment (cmd, size, seg) ->
      printSegCmd cmd size seg idx
      file.Sections
      |> Array.iter (fun s ->
        if s.SegName = seg.SegCmdName then
          out.PrintLine ()
          out.PrintSubsubsectionTitle (String.wrapSqrdBracket "Section")
          dumpSectionDetails s.SecName file)
    | Mach.SymTab (cmd, size, symtab) -> printSymTabCmd cmd size symtab idx
    | Mach.DySymTab (cmd, size, dysym) -> printDySymTabCmd cmd size dysym idx
    | Mach.DyLib (cmd, size, dylib) -> printDyLibCmd cmd size dylib idx
    | Mach.DyLdInfo (cmd, size, ldinfo) -> printDyLdInfoCmd cmd size ldinfo idx
    | Mach.FuncStarts (_, _, fnstart) -> printFuncStartsCmd fnstart idx
    | Mach.Main (cmd, size, main) -> printMainCmd cmd size main idx
    | Mach.Unhandled (cmd, size) -> printUnhandledCmd cmd size idx
    out.PrintLine ())

let dumpSharedLibs _ (file: MachBinFile) =
  let cfg = [ LeftAligned 35; LeftAligned 15; LeftAligned 15 ]
  out.PrintRow (true, cfg, [ "Lib Name"; "CurVersion"; "CompatVersion" ])
  file.Commands
  |> Array.iter (fun cmd ->
    match cmd with
    | Mach.DyLib (_, _, dyLibCmd) ->
      out.PrintRow (true, cfg,
        [ dyLibCmd.DyLibName
          toVersionString dyLibCmd.DyLibCurVer
          toVersionString dyLibCmd.DyLibCmpVer ])
    | _ -> ())
