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
open B2R2.FrontEnd.BinInterface
open B2R2.FrontEnd.BinFile
open B2R2.RearEnd
open B2R2.RearEnd.FileViewer.Helper

let badAccess _ _ =
  raise InvalidFileTypeException

let computeMagicBytes (fi: ELFFileInfo) =
  fi.ELF.BinReader.PeekBytes (16, 0) |> colorBytes

let dumpFileHeader (_: FileViewerOpts) (fi: ELFFileInfo) =
  let hdr = fi.ELF.ELFHdr
  printTwoColsWithCS "Magic:" (computeMagicBytes fi)
  printTwoCols "Class:" ("ELF" + WordSize.toString hdr.Class)
  printTwoCols "Data:" (Endian.toString hdr.Endian + " endian")
  printTwoCols "Version:" (hdr.Version.ToString ())
  printTwoCols "ABI:" (hdr.OSABI.ToString ())
  printTwoCols "ABI version:" (hdr.OSABIVersion.ToString ())
  printTwoCols "Type:" (hdr.ELFFileType.ToString ())
  printTwoCols "Machine:" (hdr.MachineType.ToString ())
  printTwoColsHi "Entry point:" (toHexString hdr.EntryPoint)
  printTwoCols "PHdr table offset:" (toHexString hdr.PHdrTblOffset)
  printTwoCols "SHdr table offset:" (toHexString hdr.SHdrTblOffset)
  printTwoCols "Flags:" (toHexString (uint64 hdr.ELFFlags))
  printTwoCols "Header size:" (toNBytes (uint64 hdr.HeaderSize))
  printTwoCols "PHdr Entry Size:" (toNBytes (uint64 hdr.PHdrEntrySize))
  printTwoCols "PHdr Entry Num:" (hdr.PHdrNum.ToString ())
  printTwoCols "SHdr Entry Size:" (toNBytes (uint64 (hdr.SHdrEntrySize)))
  printTwoCols "SHdr Entry Num:" (hdr.SHdrNum.ToString ())
  printTwoCols "SHdr string index:" (hdr.SHdrStrIdx.ToString ())

let columnWidthOfAddr (fi: ELFFileInfo) =
  if fi.ELF.ELFHdr.Class = WordSize.Bit32 then 8 else 16

let dumpSections (opts: FileViewerOpts) (fi: ELFFileInfo) =
  if opts.Verbose then
    Utils.futureFeature ()
  else
    let addrColumn = columnWidthOfAddr fi |> LeftAligned
    let cfg = [ RightAligned 5; addrColumn; addrColumn; LeftAligned 24 ]
    Printer.printrow cfg ["Num."; "Start"; "End"; "Name" ]
    fi.GetSections ()
    |> Seq.iteri (fun idx s ->
      Printer.printrow cfg
        [ idx.ToString ()
          (addrToString fi.WordSize s.Address)
          (addrToString fi.WordSize (s.Address + s.Size))
          normalizeEmpty s.Name ])

let printSectionInfo (section: ELF.ELFSection) =
  printTwoCols "Section number:" (section.SecNum.ToString ())
  printTwoCols "Section name:" section.SecName
  printTwoCols "Type:" (section.SecType.ToString ())
  printTwoCols "Address:" (toHexString section.SecAddr)
  printTwoCols "Offset:" (toHexString section.SecOffset)
  printTwoCols "Size:" (toHexString section.SecSize)
  printTwoCols "Entry Size:" (toHexString section.SecEntrySize)
  printTwoCols "Flag:" (section.SecFlags.ToString ())
  printTwoCols "Link:" (section.SecLink.ToString ())
  printTwoCols "Info:" (section.SecInfo.ToString ())
  printTwoCols "Alignment:" (toHexString section.SecAlignment)

let dumpSectionDetails (secname: string) (fi: ELFFileInfo) =
  printSectionInfo fi.ELF.SecInfo.SecByName.[secname]

let dumpSegments (opts: FileViewerOpts) (fi: ELFFileInfo) =
  if opts.Verbose then
    Utils.futureFeature ()
  else
    let addrColumn = columnWidthOfAddr fi |> LeftAligned
    let cfg = [ RightAligned 5; addrColumn; addrColumn; LeftAligned 10 ]
    Printer.println "Those are only loadable segments."
    Printer.println ()
    Printer.printrow cfg [ "Num."; "Start"; "End"; "Permission" ]
    fi.GetSegments ()
    |> Seq.iteri (fun idx s ->
      Printer.printrow cfg
        [ idx.ToString ()
          (addrToString fi.WordSize s.Address)
          (addrToString fi.WordSize (s.Address + s.Size))
          (FileInfo.PermissionToString s.Permission) ])

let targetString s =
  match s.Target with
  | TargetKind.StaticSymbol -> "(s)"
  | TargetKind.DynamicSymbol -> "(d)"
  | _ -> Utils.impossible ()

let toLibString (s: string) =
  if System.String.IsNullOrEmpty s then s else "@ " + s

let printSymbolInfo isVerbose (fi: ELFFileInfo) (symbols: seq<Symbol>) =
  let addrColumn = columnWidthOfAddr fi |> LeftAligned
  let cfg = [ LeftAligned 5; addrColumn; LeftAligned 30; LeftAligned 15 ]
  Printer.printrow cfg [ "Kind"; "Address"; "Name"; "LibraryName" ]
  symbols
  |> Seq.sortBy (fun s -> s.Name)
  |> Seq.sortBy (fun s -> s.Address)
  |> Seq.sortBy (fun s -> s.Target)
  |> Seq.iter (fun s ->
    Printer.printrow cfg
      [ targetString s
        addrToString fi.WordSize s.Address
        normalizeEmpty s.Name
        (toLibString >> normalizeEmpty) s.LibraryName ])

let dumpSymbols (opts: FileViewerOpts) (fi: ELFFileInfo) =
  fi.GetSymbols ()
  |> printSymbolInfo opts.Verbose fi

let dumpRelocs (opts: FileViewerOpts) (fi: ELFFileInfo) =
  fi.GetRelocationSymbols ()
  |> printSymbolInfo opts.Verbose fi

let dumpFunctions (opts: FileViewerOpts) (fi: ELFFileInfo) =
  fi.GetFunctionSymbols ()
  |> printSymbolInfo opts.Verbose fi

let dumpLinkageTable (opts: FileViewerOpts) (fi: ELFFileInfo) =
  if opts.Verbose then
    Utils.futureFeature ()
  else
    let addrColumn = columnWidthOfAddr fi |> LeftAligned
    let cfg = [ addrColumn; addrColumn; LeftAligned 30; LeftAligned 15 ]
    Printer.printrow cfg [ "PLT"; "GOT"; "FunctionName"; "LibraryName" ]
    fi.GetLinkageTableEntries ()
    |> Seq.iter (fun e ->
      Printer.printrow cfg
        [ (addrToString fi.WordSize e.TrampolineAddress)
          (addrToString fi.WordSize e.TableAddress)
          normalizeEmpty e.FuncName
          (toLibString >> normalizeEmpty) e.LibraryName ])

let cfaToString (hdl: BinHandle) cfa =
  ELF.CanonicalFrameAddress.toString hdl.RegisterBay cfa

let ruleToString (hdl: BinHandle) (rule: ELF.Rule) =
  rule
  |> Map.fold (fun s k v ->
    match k with
    | ELF.ReturnAddress -> s + "(ra:" + ELF.Action.toString v + ")"
    | ELF.NormalReg rid ->
      let reg = hdl.RegisterBay.RegIDToString rid
      s + "(" + reg + ":" + ELF.Action.toString v + ")") ""

let dumpEHFrame hdl (fi: ELFFileInfo) =
  let addrColumn = columnWidthOfAddr fi |> LeftAligned
  let cfg = [ addrColumn; LeftAligned 10; LeftAligned 50 ]
  fi.ELF.ExceptionFrame
  |> List.iter (fun cfi ->
    Printer.println ("- CIE: \"{0}\" cf={1} df={2}",
      cfi.CIERecord.AugmentationString,
      cfi.CIERecord.CodeAlignmentFactor.ToString ("+0;-#"),
      cfi.CIERecord.DataAlignmentFactor.ToString ("+0;-#"))
    Printer.println ()
    cfi.FDERecord
    |> Array.iter (fun fde ->
      Printer.println ("  FDE pc={0}..{1}",
        toHexString fde.PCBegin,
        toHexString fde.PCEnd)
      if fde.UnwindingInfo.IsEmpty then ()
      else
        Printer.println "  ---"
        Printer.printrow cfg [ "Location"; "CFA"; "Rules" ]
      fde.UnwindingInfo
      |> List.iter (fun i ->
        Printer.printrow cfg
          [ toHexString i.Location
            cfaToString hdl i.CanonicalFrameAddress
            ruleToString hdl i.Rule ])
      Printer.println ()
    )
  )
