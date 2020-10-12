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
open B2R2.FrontEnd.BinFile

let dumpFileHeader (fi: ELFFileInfo) (opts: CmdOptions.FileViewerOpts) =
  let hdr = fi.ELF.ELFHdr
  let magic =
    fi.ELF.BinReader.PeekBytes (16, 0)
    |> Array.fold (fun s b -> s + b.ToString ("X2") + " ") ""
  printfn " <ELF Header>"
  printfn " - Magic                       : %s" magic
  printfn " - Class                       : %s" <| match int hdr.Class with
                                                   | 32 -> "ELF32"
                                                   | 64 -> "ELF64"
                                                   | _  -> ""
  printfn " - Data                        : %s" <| Endian.toString hdr.Endian
  printfn " - Version                     : %s" <| hdr.Version.ToString ()
  printfn " - ABI                         : %s" <| hdr.OSABI.ToString ()
  printfn " - ABI Version                 : %s" <| hdr.OSABIVersion.ToString ()
  printfn " - Type                        : %s" <| hdr.ELFFileType.ToString ()
  printfn " - Machine                     : %s" <| hdr.MachineType.ToString ()
  printfn " - Entry Point                 : 0x%s"
    <| hdr.EntryPoint.ToString ("X")
  printfn " - Program Headers Offset      : 0x%s"
    <| hdr.PHdrTblOffset.ToString ()
  printfn " - Section Headers Offset      : 0x%s"
    <| hdr.SHdrTblOffset.ToString ()
  printfn " - Flags                       : %s" <| hdr.ELFFlags.ToString ()
  printfn " - Header Size                 : %s (bytes)"
    <| hdr.HeaderSize.ToString ()
  printfn " - Program Header Entry Size   : %s (bytes)"
    <| hdr.PHdrEntrySize.ToString ()
  printfn " - Program Header Entry Num    : %s" <| hdr.PHdrNum.ToString ()
  printfn " - Section Header Entry Size   : %s (bytes)"
    <| hdr.SHdrEntrySize.ToString ()
  printfn " - Section Header Entry Num    : %s" <| hdr.SHdrNum.ToString ()
  printfn " - Section Header String Index : %s" <| hdr.SHdrStrIdx.ToString ()
  if opts.HexDump then
    printfn "hexdump"

let dumpSections (fi: ELFFileInfo) (opts: CmdOptions.FileViewerOpts) =
  printfn " <ELF Section Headers>"
  if opts.Verbose then
    printfn "verbose"
  else
    printfn " %s %-16s %-16s %-s"
      "Num." "Start Address" "End Address" "Name"
    fi.GetSections ()
    |> Seq.iteri (fun idx s ->
      printfn " %3d. %16s %16s %s"
        idx
        (Helper.addrToString fi.WordSize s.Address)
        (Helper.addrToString fi.WordSize (s.Address + s.Size))
        s.Name)
  if opts.HexDump then
    printfn "hexdump"

let printSectionInfo (section: ELF.ELFSection) =
  printfn " - Num        : %d" section.SecNum
  printfn " - Name       : %s" section.SecName
  printfn " - Type       : %s" <| section.SecType.ToString ()
  printfn " - Address    : %s" <| section.SecAddr.ToString ("X")
  printfn " - Offset     : %s" <| section.SecOffset.ToString ("X")
  printfn " - Size       : %s" <| section.SecSize.ToString ("X")
  printfn " - Entry Size : %s" <| section.SecEntrySize.ToString ("X")
  printfn " - Flag       : %s" <| section.SecFlags.ToString ()
  printfn " - Link       : %s" <| section.SecLink.ToString ()
  printfn " - Info       : %s" <| section.SecInfo.ToString ()
  printfn " - Alignment  : %s" <| section.SecAlignment.ToString ("X")

let dumpTextSection (fi: ELFFileInfo) (opts: CmdOptions.FileViewerOpts) =
  printfn " <ELF Text Section>"
  fi.GetTextSections ()
  |> Seq.iter (fun s ->
    printSectionInfo fi.ELF.SecInfo.SecByName.[s.Name])
  if opts.HexDump then
    printfn "hexdump"

let dumpSectionDetails (fi: ELFFileInfo) (opts: CmdOptions.FileViewerOpts) =
  printfn " <ELF Section Details>"
  printSectionInfo fi.ELF.SecInfo.SecByName.[opts.DisplayTargets.["d"].[0]]
  if opts.HexDump then
    printfn "Hex dump:"

let dumpSegments (fi: ELFFileInfo) (opts: CmdOptions.FileViewerOpts) =
  printfn " <ELF Program Segment Headers>"
  if opts.Verbose then
    printfn "verbose"
  else
    printfn " Those are only loadable segments"
    printfn " %s  %-16s  %-16s  %-s"
      "Num." "Start Address" "End Address" "Permission"
    fi.GetSegments ()
    |> Seq.iteri (fun idx s ->
      printfn " %3d.  %16s  %16s  [%s]"
        idx
        (Helper.addrToString fi.WordSize s.Address)
        (Helper.addrToString fi.WordSize (s.Address + s.Size))
        (FileInfo.PermissionToString s.Permission))
  if opts.HexDump then
    printfn "hexdump"

let printSymbolInfo (fi: ELFFileInfo) (symbols: seq<Symbol>) =
  let targetString s =
    match s.Target with
    | TargetKind.StaticSymbol -> "(s)"
    | TargetKind.DynamicSymbol -> "(d)"
    | _ -> failwith "Invalid symbol target kind."
  let name (s: Symbol) = if s.Name.Length > 0 then s.Name else ""
  printfn " s: static, d: dynamic"
  printfn " %s  %-16s  %-80s  %-s"
   "Kind" "Address" "Name" "LibraryName"
  symbols
  |> Seq.sortBy (fun s -> s.Name)
  |> Seq.sortBy (fun s -> s.Address)
  |> Seq.sortBy (fun s -> s.Target)
  |> Seq.iter (fun s ->
    printfn " %4s  %16s  %-80s  %-s"
      (targetString s) (Helper.addrToString fi.WordSize s.Address)
      (name s) (Helper.dumpIfNotEmpty s.LibraryName))

let dumpSymbols (fi: ELFFileInfo) (opts: CmdOptions.FileViewerOpts) =
  printfn " <ELF Symbols>"
  let filterNoType (s: Symbol) =
    s.Target = TargetKind.DynamicSymbol
    || (s.Kind <> SymbolKind.NoType && s.Name.Length > 0)
  if opts.Verbose then
    printfn "verbose"
  else
    fi.GetSymbols ()
    |> (fun symbs -> Seq.filter filterNoType symbs)
    |> printSymbolInfo fi
  if opts.HexDump then
    printfn "hexdump"

let dumpRelocs (fi: ELFFileInfo) (opts: CmdOptions.FileViewerOpts) =
  printfn " <ELF Relocation Symbols>"
  if opts.Verbose then
    printfn "verbose"
  else
    fi.GetRelocationSymbols ()
    |> printSymbolInfo fi
  if opts.HexDump then
    printfn "hexdump"

let dumpFunctions (fi: ELFFileInfo) (opts: CmdOptions.FileViewerOpts) =
  printfn " <ELF Function Symbols>"
  if opts.Verbose then
    printfn "verbose"
  else
    fi.GetFunctionSymbols ()
    |> printSymbolInfo fi
  if opts.HexDump then
    printfn "hexdump"

let dumpLinkageTable (fi: ELFFileInfo) (opts: CmdOptions.FileViewerOpts) =
  printfn " <ELF Linkage Table (PLT -> GOT) Information>"
  if opts.Verbose then
    printfn "verbose"
  else
    printfn " %-16s  %-16s  %-20s  %-s"
      "PLT" "GOT" "FunctionName" "LibraryName"
    fi.GetLinkageTableEntries ()
     |> Seq.iter (fun a ->
       printfn " %16s  %16s  %-20s  %-s"
         (Helper.addrToString fi.WordSize a.TrampolineAddress)
         (Helper.addrToString fi.WordSize a.TableAddress)
         a.FuncName
         (Helper.dumpIfNotEmpty a.LibraryName))
  if opts.HexDump then
    printfn "hexdump"
