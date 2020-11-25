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

type private P = Printer

let dumpBasic (fi: FileInfo) =
  P.printSectionTitle "Basic Information"
  P.printTwoCols "File format:" (FileFormat.toString fi.FileFormat)
  P.printTwoCols "Architecture:" (ISA.ArchToString fi.ISA.Arch)
  P.printTwoCols "Endianness:" (Endian.toString fi.ISA.Endian)
  P.printTwoCols "Word size:" (WordSize.toString fi.WordSize + " bit")
  P.printTwoCols "File type:" (FileInfo.FileTypeToString fi.FileType)
  P.printTwoColsHi "Entry point:" (FileInfo.EntryPointToString fi.EntryPoint)
  P.println ()

let dumpSecurity (fi: FileInfo) =
  P.printSectionTitle "Security Information"
  P.printTwoCols "Stripped binary:" (fi.IsStripped.ToString ())
  P.printTwoCols "DEP (NX) enabled:" (fi.IsNXEnabled.ToString ())
  P.printTwoCols "Relocatable (PIE):" (fi.IsRelocatable.ToString ())
  P.println ()

let dumpSpecific opts (fi: FileInfo) title elf pe mach =
  P.printSectionTitle title
  match fi with
  | :? ELFFileInfo as fi -> elf opts fi
  | :? PEFileInfo as fi -> pe opts fi
  | :? MachFileInfo as fi -> mach opts fi
  | _ -> Utils.futureFeature ()
  P.println ()

let dumpFileHeader (opts: FileViewerOpts) (fi: FileInfo) =
  dumpSpecific opts fi "File Header Information"
    ELFViewer.dumpFileHeader
    PEViewer.dumpFileHeader
    MachViewer.dumpFileHeader

let dumpSectionHeaders (opts: FileViewerOpts) (fi: FileInfo) =
  dumpSpecific opts fi "Section Header Information"
    ELFViewer.dumpSectionHeaders
    PEViewer.dumpSectionHeaders
    MachViewer.dumpSectionHeaders

let dumpSectionDetails (secname: string) (fi: FileInfo) =
  dumpSpecific secname fi "Section Details"
    ELFViewer.dumpSectionDetails
    PEViewer.dumpSectionDetails
    MachViewer.dumpSectionDetails

let dumpSymbols (opts: FileViewerOpts) (fi: FileInfo) =
  dumpSpecific opts fi "Symbol Information"
    ELFViewer.dumpSymbols
    PEViewer.dumpSymbols
    MachViewer.dumpSymbols

let dumpRelocs (opts: FileViewerOpts) (fi: FileInfo) =
  dumpSpecific opts fi "Relocation Information"
    ELFViewer.dumpRelocs
    PEViewer.dumpRelocs
    MachViewer.dumpRelocs

let dumpFunctions (opts: FileViewerOpts) (fi: FileInfo) =
  dumpSpecific opts fi "Function Information"
    ELFViewer.dumpFunctions
    PEViewer.dumpFunctions
    MachViewer.dumpFunctions

let dumpSegments (opts: FileViewerOpts) (fi: FileInfo) =
  dumpSpecific opts fi "Segment Information"
    ELFViewer.dumpSegments PEViewer.badAccess MachViewer.badAccess

let dumpLinkageTable (opts: FileViewerOpts) (fi: FileInfo) =
  dumpSpecific opts fi "Linkage Table Information"
    ELFViewer.dumpLinkageTable PEViewer.badAccess MachViewer.badAccess

let dumpEHFrame hdl (fi: FileInfo) =
  dumpSpecific hdl fi ".eh_frame Information"
    ELFViewer.dumpEHFrame PEViewer.badAccess MachViewer.badAccess

let dumpNotes hdl (fi: FileInfo) =
  dumpSpecific hdl fi ".notes Information"
    ELFViewer.dumpNotes PEViewer.badAccess MachViewer.badAccess

let dumpImports (opts: FileViewerOpts) (fi: FileInfo) =
  dumpSpecific opts fi "Import table Information"
    ELFViewer.badAccess PEViewer.dumpImports MachViewer.badAccess

let dumpExports (opts: FileViewerOpts) (fi: FileInfo) =
  dumpSpecific opts fi "Export table Information"
    ELFViewer.badAccess PEViewer.dumpExports MachViewer.badAccess

let dumpOptionalHeader (opts: FileViewerOpts) (fi: FileInfo) =
  dumpSpecific opts fi "Optional Header Information"
    ELFViewer.badAccess PEViewer.dumpOptionalHeader MachViewer.badAccess

let dumpCLRHeader (opts: FileViewerOpts) (fi: FileInfo) =
  dumpSpecific opts fi "CLR Header Information"
    ELFViewer.badAccess PEViewer.dumpCLRHeader MachViewer.badAccess

let dumpDependencies (opts: FileViewerOpts) (fi: FileInfo) =
  dumpSpecific opts fi "Dependencies Information"
    ELFViewer.badAccess PEViewer.dumpDependencies MachViewer.badAccess

let dumpArchiveHeader (opts: FileViewerOpts) (fi: FileInfo) =
  dumpSpecific opts fi "Archive Header Information"
    ELFViewer.badAccess PEViewer.badAccess MachViewer.dumpArchiveHeader

let dumpUniversalHeader (opts: FileViewerOpts) (fi: FileInfo) =
  dumpSpecific opts fi "Universal Header Information"
    ELFViewer.badAccess PEViewer.badAccess MachViewer.dumpUniversalHeader

let dumpLoadCommands (opts: FileViewerOpts) (fi: FileInfo) =
  dumpSpecific opts fi "Load Commands Information"
    ELFViewer.badAccess PEViewer.badAccess MachViewer.dumpLoadCommands

let dumpSharedLibs (opts: FileViewerOpts) (fi: FileInfo) =
  dumpSpecific opts fi "Shared Libs Information"
    ELFViewer.badAccess PEViewer.badAccess MachViewer.dumpSharedLibs

let printFileName filepath =
  [ Green, "["; Yellow, filepath; Green, "]" ] |> P.println
  P.println ()

let printBasic fi =
  dumpBasic fi
  dumpSecurity fi

let printAll opts hdl (fi: FileInfo) =
  dumpBasic fi
  dumpSecurity fi
  dumpFileHeader opts fi
  dumpSectionHeaders opts fi
  dumpSymbols opts fi
  dumpRelocs opts fi
  dumpFunctions opts fi
  match fi with
   | :? ELFFileInfo as fi ->
     dumpSegments opts fi
     dumpLinkageTable opts fi
     dumpEHFrame hdl fi
   | :? PEFileInfo as fi ->
     dumpImports opts fi
     dumpExports opts fi
     dumpOptionalHeader opts fi
     dumpCLRHeader opts fi
     dumpDependencies opts fi
   | :? MachFileInfo as fi ->
     dumpLoadCommands opts fi
     dumpSharedLibs opts fi
   | _ -> Utils.futureFeature ()

let printSelectively hdl opts fi = function
  | DisplayAll -> Utils.impossible ()
  | DisplayFileHeader -> dumpFileHeader opts fi
  | DisplaySectionHeaders -> dumpSectionHeaders opts fi
  | DisplaySectionDetails s -> dumpSectionDetails s fi
  | DisplaySymbols -> dumpSymbols opts fi
  | DisplayRelocations -> dumpRelocs opts fi
  | DisplayFunctions -> dumpFunctions opts fi
  | DisplayELFSpecific ELFDisplayProgramHeader -> dumpSegments opts fi
  | DisplayELFSpecific ELFDisplayPLT -> dumpLinkageTable opts fi
  | DisplayELFSpecific ELFDisplayEHFrame -> dumpEHFrame hdl fi
  | DisplayELFSpecific ELFDisplayNotes -> dumpNotes hdl fi
  | DisplayPESpecific PEDisplayImports -> dumpImports opts fi
  | DisplayPESpecific PEDisplayExports -> dumpExports opts fi
  | DisplayPESpecific PEDisplayOptionalHeader -> dumpOptionalHeader opts fi
  | DisplayPESpecific PEDisplayCLRHeader -> dumpCLRHeader opts fi
  | DisplayPESpecific PEDisplayDependencies -> dumpDependencies opts fi
  | DisplayMachSpecific MachDisplayArchiveHeader -> dumpArchiveHeader opts fi
  | DisplayMachSpecific MachDisplayUniversalHeader -> dumpUniversalHeader opts fi
  | DisplayMachSpecific MachDisplayLoadCommands -> dumpLoadCommands opts fi
  | DisplayMachSpecific MachDisplaySharedLibs -> dumpSharedLibs opts fi

let dumpFile (opts: FileViewerOpts) (filepath: string) =
  let hdl = BinHandle.Init (opts.ISA, opts.BaseAddress, filepath)
  let fi = hdl.FileInfo
  printFileName fi.FilePath
  if opts.DisplayItems.Count = 0 then printBasic fi
  elif opts.DisplayItems.Contains DisplayAll then printAll opts hdl fi
  else opts.DisplayItems |> Seq.iter (printSelectively hdl opts fi)

let [<Literal>] private toolName = "fileview"
let [<Literal>] private usageTail = "<binary file(s)>"

let dump files opts =
  CmdOpts.SanitizeRestArgs files
  match files with
  | [] ->
    P.printError "File(s) must be given."
    CmdOpts.PrintUsage toolName usageTail Cmd.spec
  | files -> files |> List.iter (dumpFile opts)

[<EntryPoint>]
let main args =
  let opts = FileViewerOpts ()
  CmdOpts.ParseAndRun dump toolName usageTail Cmd.spec opts args
