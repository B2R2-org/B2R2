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
open B2R2.Logging
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd
open B2R2.RearEnd.Utils

let dumpBasic (file: IBinFile) =
  let entry = ColoredString(Green, String.ofEntryPointOpt file.EntryPoint)
  Log.Out.PrintSectionTitle "Basic Information"
  Log.Out
  <== [ "File format:"; FileFormat.toString file.Format ]
  <== [ "Architecture:"; file.ISA.ToString() ]
  <== [ "Endianness:"; Endian.toString file.ISA.Endian ]
  <== [ "Word size:"; WordSize.toString file.ISA.WordSize + " bit" ]
  <=/ [ OutputNormal "Entry point:"; OutputColored entry ]
  Log.Out.PrintLine()

let dumpSecurity (file: IBinFile) =
  Log.Out.PrintSectionTitle "Security Information"
  Log.Out
  <== [ "Stripped binary:"; file.IsStripped.ToString() ]
  <== [ "DEP (NX) enabled:"; file.IsNXEnabled.ToString() ]
  <=/ [ "Relocatable (PIE):"; file.IsRelocatable.ToString() ]
  Log.Out.PrintLine()

let dumpSpecific opts (file: IBinFile) title elf pe mach =
  Log.Out.PrintSectionTitle title
  match file with
  | :? ELFBinFile as file -> elf opts file
  | :? PEBinFile as file -> pe opts file
  | :? MachBinFile as file -> mach opts file
  | _ -> Terminator.futureFeature ()
  Log.Out.PrintLine()

let dumpFileHeader (opts: FileViewerOpts) (file: IBinFile) =
  dumpSpecific opts file "File Header Information"
    ELFViewer.dumpFileHeader
    PEViewer.dumpFileHeader
    MachViewer.dumpFileHeader

let dumpSectionHeaders (opts: FileViewerOpts) (file: IBinFile) =
  dumpSpecific opts file "Section Header Information"
    ELFViewer.dumpSectionHeaders
    PEViewer.dumpSectionHeaders
    MachViewer.dumpSectionHeaders

let dumpSectionDetails (secname: string) (file: IBinFile) =
  dumpSpecific secname file "Section Details"
    ELFViewer.dumpSectionDetails
    PEViewer.dumpSectionDetails
    MachViewer.dumpSectionDetails

let dumpSymbols (opts: FileViewerOpts) (file: IBinFile) =
  dumpSpecific opts file "Symbol Information"
    ELFViewer.dumpSymbols
    PEViewer.dumpSymbols
    MachViewer.dumpSymbols

let dumpRelocs (opts: FileViewerOpts) (file: IBinFile) =
  dumpSpecific opts file "Relocation Information"
    ELFViewer.dumpRelocs
    PEViewer.dumpRelocs
    MachViewer.dumpRelocs

let dumpFunctions (opts: FileViewerOpts) (file: IBinFile) =
  dumpSpecific opts file "Function Information"
    ELFViewer.dumpFunctions
    PEViewer.dumpFunctions
    MachViewer.dumpFunctions

let dumpExceptionTable hdl (opts: FileViewerOpts) (file: IBinFile) =
  dumpSpecific opts file "Exception Table"
    (ELFViewer.dumpExceptionTable hdl)
    PEViewer.badAccess
    MachViewer.badAccess

let dumpDynamicSection (opts: FileViewerOpts) (file: IBinFile) =
  dumpSpecific opts file "Dynamic Section Information"
    ELFViewer.dumpDynamicSection PEViewer.badAccess MachViewer.badAccess

let dumpSegments (opts: FileViewerOpts) (file: IBinFile) =
  dumpSpecific opts file "Segment Information"
    ELFViewer.dumpSegments PEViewer.badAccess MachViewer.badAccess

let dumpLinkageTable (opts: FileViewerOpts) (file: IBinFile) =
  dumpSpecific opts file "Linkage Table Information"
    ELFViewer.dumpLinkageTable PEViewer.badAccess MachViewer.badAccess

let dumpEHFrame hdl (file: IBinFile) =
  dumpSpecific hdl file ".eh_frame Information"
    ELFViewer.dumpEHFrame PEViewer.badAccess MachViewer.badAccess

let dumpGccExceptTable hdl (file: IBinFile) =
  dumpSpecific hdl file ".gcc_except_table Information"
    ELFViewer.dumpGccExceptTable PEViewer.badAccess MachViewer.badAccess

let dumpNotes hdl (file: IBinFile) =
  dumpSpecific hdl file ".notes Information"
    ELFViewer.dumpNotes PEViewer.badAccess MachViewer.badAccess

let dumpImports (opts: FileViewerOpts) (file: IBinFile) =
  dumpSpecific opts file "Import table Information"
    ELFViewer.badAccess PEViewer.dumpImports MachViewer.badAccess

let dumpExports (opts: FileViewerOpts) (file: IBinFile) =
  dumpSpecific opts file "Export table Information"
    ELFViewer.badAccess PEViewer.dumpExports MachViewer.badAccess

let dumpOptionalHeader (opts: FileViewerOpts) (file: IBinFile) =
  dumpSpecific opts file "Optional Header Information"
    ELFViewer.badAccess PEViewer.dumpOptionalHeader MachViewer.badAccess

let dumpCLRHeader (opts: FileViewerOpts) (file: IBinFile) =
  dumpSpecific opts file "CLR Header Information"
    ELFViewer.badAccess PEViewer.dumpCLRHeader MachViewer.badAccess

let dumpDependencies (opts: FileViewerOpts) (file: IBinFile) =
  dumpSpecific opts file "Dependencies Information"
    ELFViewer.badAccess PEViewer.dumpDependencies MachViewer.badAccess

let dumpArchiveHeader (opts: FileViewerOpts) (file: IBinFile) =
  dumpSpecific opts file "Archive Header Information"
    ELFViewer.badAccess PEViewer.badAccess MachViewer.dumpArchiveHeader

let dumpUnivHeader (opts: FileViewerOpts) (file: IBinFile) =
  dumpSpecific opts file "Universal Header Information"
    ELFViewer.badAccess PEViewer.badAccess MachViewer.dumpUniversalHeader

let dumpLoadCommands (opts: FileViewerOpts) (file: IBinFile) =
  dumpSpecific opts file "Load Commands Information"
    ELFViewer.badAccess PEViewer.badAccess MachViewer.dumpLoadCommands

let dumpSharedLibs (opts: FileViewerOpts) (file: IBinFile) =
  dumpSpecific opts file "Shared Libs Information"
    ELFViewer.badAccess PEViewer.badAccess MachViewer.dumpSharedLibs

let printFileName filepath =
  ColoredString()
    .Add(Green, "[")
    .Add(Yellow, filepath)
    .Add(Green, "]")
  |> Log.Out.PrintLine
  Log.Out.PrintLine()

let printBasic file =
  dumpBasic file
  dumpSecurity file

let printAll opts hdl (file: IBinFile) =
  dumpBasic file
  dumpSecurity file
  dumpFileHeader opts file
  dumpSectionHeaders opts file
  dumpSymbols opts file
  dumpRelocs opts file
  dumpFunctions opts file
  dumpExceptionTable hdl opts file
  match file with
  | :? ELFBinFile as file ->
    dumpDynamicSection opts file
    dumpSegments opts file
    dumpLinkageTable opts file
    dumpEHFrame hdl file
    dumpGccExceptTable hdl file
  | :? PEBinFile as file ->
    dumpImports opts file
    dumpExports opts file
    dumpOptionalHeader opts file
    dumpCLRHeader opts file
    dumpDependencies opts file
  | :? MachBinFile as file ->
    dumpLoadCommands opts file
    dumpSharedLibs opts file
  | _ -> Terminator.futureFeature ()

let printSelectively hdl opts file = function
  | DisplayAll -> Terminator.impossible ()
  | DisplayFileHeader -> dumpFileHeader opts file
  | DisplaySectionHeaders -> dumpSectionHeaders opts file
  | DisplaySectionDetails s -> dumpSectionDetails s file
  | DisplaySymbols -> dumpSymbols opts file
  | DisplayRelocations -> dumpRelocs opts file
  | DisplayFunctions -> dumpFunctions opts file
  | DisplayExceptionTable -> dumpExceptionTable hdl opts file
  | DisplayELFSpecific ELFDisplayProgramHeader -> dumpSegments opts file
  | DisplayELFSpecific ELFDisplayPLT -> dumpLinkageTable opts file
  | DisplayELFSpecific ELFDisplayEHFrame -> dumpEHFrame hdl file
  | DisplayELFSpecific ELFDisplayGccExceptTable -> dumpGccExceptTable hdl file
  | DisplayELFSpecific ELFDisplayNotes -> dumpNotes hdl file
  | DisplayPESpecific PEDisplayImports -> dumpImports opts file
  | DisplayPESpecific PEDisplayExports -> dumpExports opts file
  | DisplayPESpecific PEDisplayOptionalHeader -> dumpOptionalHeader opts file
  | DisplayPESpecific PEDisplayCLRHeader -> dumpCLRHeader opts file
  | DisplayPESpecific PEDisplayDependencies -> dumpDependencies opts file
  | DisplayMachSpecific MachDisplayArchiveHeader -> dumpArchiveHeader opts file
  | DisplayMachSpecific MachDisplayUniversalHeader -> dumpUnivHeader opts file
  | DisplayMachSpecific MachDisplayLoadCommands -> dumpLoadCommands opts file
  | DisplayMachSpecific MachDisplaySharedLibs -> dumpSharedLibs opts file

let dumpFile (opts: FileViewerOpts) (filePath: string) =
  let hdl = BinHandle(filePath, opts.ISA, opts.BaseAddress)
  let file = hdl.File
  printFileName file.Path
  if opts.DisplayItems.Count = 0 then printBasic file
  elif opts.DisplayItems.Contains DisplayAll then printAll opts hdl file
  else opts.DisplayItems |> Seq.iter (printSelectively hdl opts file)

let [<Literal>] private ToolName = "fileview"

let [<Literal>] private UsageTail = "<binary file(s)>"

let dump files opts =
  CmdOpts.sanitizeRestArgs files
  match files with
  | [] ->
    Log.Out <=? "File(s) must be given."
    CmdOpts.printUsage ToolName UsageTail FileViewerOpts.Spec
  | files ->
#if DEBUG
    let sw = System.Diagnostics.Stopwatch.StartNew()
#endif
    try files |> List.iter (dumpFile opts)
    finally Log.Out.Flush()
#if DEBUG
    sw.Stop()
    let sec = sw.Elapsed.TotalSeconds
    System.Console.Error.WriteLine $"Total time: {sec} sec."
#endif

[<EntryPoint>]
let main args =
  let opts = FileViewerOpts.Default
  Log.Out <=/ { TableConfig.DefaultTwoColumn with Indentation = 2 }
  CmdOpts.parseAndRun dump ToolName UsageTail FileViewerOpts.Spec opts args
