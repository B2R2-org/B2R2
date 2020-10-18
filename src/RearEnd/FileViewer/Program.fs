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

module B2R2.RearEnd.FileViewer.Program

open B2R2
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinInterface
open B2R2.RearEnd
open B2R2.RearEnd.FileViewer.Helper

let dumpBasic (fi: FileInfo) =
  printSectionTitle "Basic Information"
  printTwoCols "File format:" (FileFormat.toString fi.FileFormat)
  printTwoCols "Architecture:" (ISA.ArchToString fi.ISA.Arch)
  printTwoCols "Endianness:" (Endian.toString fi.ISA.Endian)
  printTwoCols "Word size:" (WordSize.toString fi.WordSize + " bit")
  printTwoCols "File type:" (FileInfo.FileTypeToString fi.FileType)
  printTwoColsHi "Entry point:" (FileInfo.EntryPointToString fi.EntryPoint)
  Printer.println ()

let dumpSecurity (fi: FileInfo) =
  printSectionTitle "Security Information"
  printTwoCols "Stripped binary:" (fi.IsStripped.ToString ())
  printTwoCols "DEP (NX) enabled:" (fi.IsNXEnabled.ToString ())
  printTwoCols "Relocatable (PIE):" (fi.IsRelocatable.ToString ())
  Printer.println ()

let dumpSpecific opts (fi: FileInfo) title elf pe mach =
  printSectionTitle title
  match fi with
  | :? ELFFileInfo as fi -> elf opts fi
  | :? PEFileInfo as fi -> pe opts fi
  | :? MachFileInfo as fi -> mach opts fi
  | _ -> Utils.futureFeature ()
  Printer.println ()

let dumpFileHeader (opts: FileViewerOpts) (fi: FileInfo) =
  dumpSpecific opts fi "File Header"
    ELFViewer.dumpFileHeader
    PEViewer.dumpFileHeader
    MachViewer.dumpFileHeader

let dumpSymbols (opts: FileViewerOpts) (fi: FileInfo) =
  dumpSpecific opts fi "Symbol Information"
    ELFViewer.dumpSymbols
    PEViewer.dumpSymbols
    MachViewer.dumpSymbols

let dumpFunctions (opts: FileViewerOpts) (fi: FileInfo) =
  dumpSpecific opts fi "Functions Information"
    ELFViewer.dumpFunctions
    PEViewer.dumpFunctions
    MachViewer.dumpFunctions

let dumpSections (opts: FileViewerOpts) (fi: FileInfo) =
  dumpSpecific opts fi "Section Information"
    ELFViewer.dumpSections
    PEViewer.dumpSections
    MachViewer.dumpSections

let dumpSectionDetails (secname: string) (fi: FileInfo) =
  dumpSpecific secname fi "Section Details"
    ELFViewer.dumpSectionDetails
    PEViewer.dumpSectionDetails
    MachViewer.dumpSectionDetails

let dumpSegments (opts: FileViewerOpts) (fi: FileInfo) =
  dumpSpecific opts fi "Segment Information"
    ELFViewer.dumpSegments
    PEViewer.dumpSegments
    MachViewer.dumpSegments

let dumpRelocs (opts: FileViewerOpts) (fi: FileInfo) =
  dumpSpecific opts fi "Relocation Information"
    ELFViewer.dumpRelocs
    PEViewer.dumpRelocs
    MachViewer.dumpRelocs

let dumpLinkageTable (opts: FileViewerOpts) (fi: FileInfo) =
  dumpSpecific opts fi "Linkage Table Information"
    ELFViewer.dumpLinkageTable
    PEViewer.dumpLinkageTable
    MachViewer.dumpLinkageTable

let dumpEHFrame hdl (fi: FileInfo) =
  dumpSpecific hdl fi ".eh_frame Information"
    ELFViewer.dumpEHFrame PEViewer.badAccess MachViewer.badAccess

let printFileName filepath =
  [ Green, "["; Yellow, filepath; Green, "]" ] |> Printer.println
  Printer.println ()

let printBasic fi =
  dumpBasic fi
  dumpSecurity fi

let printAll opts (fi: FileInfo) =
  dumpBasic fi
  dumpSecurity fi
  dumpFileHeader opts fi
  dumpSections opts fi
  dumpSegments opts fi
  dumpSymbols opts fi
  dumpRelocs opts fi
  dumpFunctions opts fi
  dumpLinkageTable opts fi

let printSelectively hdl opts fi = function
  | DisplayAll -> Utils.impossible ()
  | DisplayFileHeader -> dumpFileHeader opts fi
  | DisplaySymbols -> dumpSymbols opts fi
  | DisplayFunctions -> dumpFunctions opts fi
  | DisplayELFSpecific ELFDisplayProgramHeader -> dumpSegments opts fi
  | DisplayELFSpecific ELFDisplaySectionHeader -> dumpSections opts fi
  | DisplayELFSpecific (ELFDisplaySectionDetails s) -> dumpSectionDetails s fi
  | DisplayELFSpecific ELFDisplayRelocations -> dumpRelocs opts fi
  | DisplayELFSpecific ELFDisplayPLT -> dumpLinkageTable opts fi
  | DisplayELFSpecific ELFDisplayEHFrame -> dumpEHFrame hdl fi
  | _ -> Utils.futureFeature ()

let dumpFile (opts: FileViewerOpts) (filepath: string) =
  let hdl = BinHandle.Init (opts.ISA, opts.BaseAddress, filepath)
  let fi = hdl.FileInfo
  printFileName fi.FilePath
  if opts.DisplayItems.Count = 0 then printBasic fi
  elif opts.DisplayItems.Contains DisplayAll then printAll opts fi
  else opts.DisplayItems |> Seq.iter (printSelectively hdl opts fi)

let [<Literal>] private toolName = "fileview"
let [<Literal>] private usageTail = "<binary file(s)>"

let dump files opts =
  match files with
  | [] ->
    printError "File(s) must be given."
    CmdOpts.PrintUsage toolName usageTail Cmd.spec
  | files -> files |> List.iter (dumpFile opts)

[<EntryPoint>]
let main args =
  let opts = FileViewerOpts ()
  CmdOpts.ParseAndRun dump toolName usageTail Cmd.spec opts args
