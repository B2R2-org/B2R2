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
open B2R2.FrontEnd
open B2R2.RearEnd.Utils

let private printFileName filepath =
  ColoredString()
    .Add(Green, "[")
    .Add(Yellow, filepath)
    .Add(Green, "]")
  |> printcn
  printsn ""

let private dumpBasic (file: IBinFile) =
  let entry = ColoredString(Green, String.ofEntryPointOpt file.EntryPoint)
  printSectionTitle "Basic Information"
  printsr [| "File format:"; FileFormat.toString file.Format |]
  printsr [| "Architecture:"; file.ISA.ToString() |]
  printsr [| "Endianness:"; Endian.toString file.ISA.Endian |]
  printsr [| "Word size:"; WordSize.toString file.ISA.WordSize + " bit" |]
  printor [| OutputNormal "Entry point:"; OutputColored entry |]
  printsn ""

let private dumpSecurity (file: IBinFile) =
  printSectionTitle "Security Information"
  printsr [| "Stripped binary:"; file.IsStripped.ToString() |]
  printsr [| "DEP (NX) enabled:"; file.IsNXEnabled.ToString() |]
  printsr [| "Relocatable (PIE):"; file.IsRelocatable.ToString() |]
  printsn ""

let private printBasic file =
  dumpBasic file
  dumpSecurity file

let private dumpSpecific opts (file: IBinFile) title elf pe mach =
  printSectionTitle title
  match file with
  | :? ELFBinFile as file -> elf opts file
  | :? PEBinFile as file -> pe opts file
  | :? MachBinFile as file -> mach opts file
  | _ -> Terminator.futureFeature ()

let private dumpFileHeader (opts: FileViewerOpts) (file: IBinFile) =
  dumpSpecific opts file "File Header Information"
    ELFViewer.dumpFileHeader
    PEViewer.dumpFileHeader
    MachViewer.dumpFileHeader

let private dumpSectionHeaders (opts: FileViewerOpts) (file: IBinFile) =
  dumpSpecific opts file "Section Header Information"
    ELFViewer.dumpSectionHeaders
    PEViewer.dumpSectionHeaders
    MachViewer.dumpSectionHeaders

let private dumpSectionDetails (secname: string) (file: IBinFile) =
  dumpSpecific secname file "Section Details"
    ELFViewer.dumpSectionDetails
    PEViewer.dumpSectionDetails
    MachViewer.dumpSectionDetails

let private dumpSymbols (opts: FileViewerOpts) (file: IBinFile) =
  dumpSpecific opts file "Symbol Information"
    ELFViewer.dumpSymbols
    PEViewer.dumpSymbols
    MachViewer.dumpSymbols

let private dumpRelocs (opts: FileViewerOpts) (file: IBinFile) =
  dumpSpecific opts file "Relocation Information"
    ELFViewer.dumpRelocs
    PEViewer.dumpRelocs
    MachViewer.dumpRelocs

let private dumpFunctions (opts: FileViewerOpts) (file: IBinFile) =
  dumpSpecific opts file "Function Information"
    ELFViewer.dumpFunctions
    PEViewer.dumpFunctions
    MachViewer.dumpFunctions

let private dumpExceptionTable hdl (file: IBinFile) =
  dumpSpecific hdl file "Exception Table"
    ELFViewer.dumpExceptionTable
    PEViewer.dumpExceptionTable
    MachViewer.dumpExceptionTable

let private dumpDynamicSection (opts: FileViewerOpts) (file: IBinFile) =
  dumpSpecific opts file "Dynamic Section Information"
    ELFViewer.dumpDynamicSection badAccess badAccess

let private dumpSegments (opts: FileViewerOpts) (file: IBinFile) =
  dumpSpecific opts file "Segment Information"
    ELFViewer.dumpSegments badAccess badAccess

let private dumpLinkageTable (opts: FileViewerOpts) (file: IBinFile) =
  dumpSpecific opts file "Linkage Table Information"
    ELFViewer.dumpLinkageTable badAccess badAccess

let private dumpEHFrame hdl (file: IBinFile) =
  dumpSpecific hdl file ".eh_frame Information"
    ELFViewer.dumpEHFrame badAccess badAccess

let private dumpGccExceptTable hdl (file: IBinFile) =
  dumpSpecific hdl file ".gcc_except_table Information"
    ELFViewer.dumpGccExceptTable badAccess badAccess

let private dumpNotes hdl (file: IBinFile) =
  dumpSpecific hdl file ".notes Information"
    ELFViewer.dumpNotes badAccess badAccess

let private dumpImports (opts: FileViewerOpts) (file: IBinFile) =
  dumpSpecific opts file "Import table Information"
    badAccess PEViewer.dumpImports badAccess

let private dumpExports (opts: FileViewerOpts) (file: IBinFile) =
  dumpSpecific opts file "Export table Information"
    badAccess PEViewer.dumpExports badAccess

let private dumpOptionalHeader (opts: FileViewerOpts) (file: IBinFile) =
  dumpSpecific opts file "Optional Header Information"
    badAccess PEViewer.dumpOptionalHeader badAccess

let private dumpCLRHeader (opts: FileViewerOpts) (file: IBinFile) =
  dumpSpecific opts file "CLR Header Information"
    badAccess PEViewer.dumpCLRHeader badAccess

let private dumpDependencies (opts: FileViewerOpts) (file: IBinFile) =
  dumpSpecific opts file "Dependencies Information"
    badAccess PEViewer.dumpDependencies badAccess

let private dumpArchiveHeader (opts: FileViewerOpts) (file: IBinFile) =
  dumpSpecific opts file "Archive Header Information"
    badAccess badAccess MachViewer.dumpArchiveHeader

let private dumpUnivHeader (opts: FileViewerOpts) (file: IBinFile) =
  dumpSpecific opts file "Universal Header Information"
    badAccess badAccess MachViewer.dumpUniversalHeader

let private dumpLoadCommands (opts: FileViewerOpts) (file: IBinFile) =
  dumpSpecific opts file "Load Commands Information"
    badAccess badAccess MachViewer.dumpLoadCommands

let private dumpSharedLibs (opts: FileViewerOpts) (file: IBinFile) =
  dumpSpecific opts file "Shared Libs Information"
    badAccess badAccess MachViewer.dumpSharedLibs

let private printCommon opts file =
  dumpBasic file
  dumpSecurity file
  dumpFileHeader opts file
  dumpSectionHeaders opts file
  dumpSymbols opts file
  dumpRelocs opts file
  dumpFunctions opts file

let private printAll opts hdl (file: IBinFile) =
  printCommon opts file
  match file with
  | :? ELFBinFile as file ->
    dumpDynamicSection opts file
    dumpSegments opts file
    dumpLinkageTable opts file
    dumpExceptionTable hdl file
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

let private printSelectively hdl opts file = function
  | DisplayAll -> Terminator.impossible ()
  | DisplayFileHeader -> dumpFileHeader opts file
  | DisplaySectionHeaders -> dumpSectionHeaders opts file
  | DisplaySectionDetails s -> dumpSectionDetails s file
  | DisplaySymbols -> dumpSymbols opts file
  | DisplayRelocations -> dumpRelocs opts file
  | DisplayFunctions -> dumpFunctions opts file
  | DisplayExceptionTable -> dumpExceptionTable hdl file
  | DisplayELF ELFProgHeader -> dumpSegments opts file
  | DisplayELF ELFPLT -> dumpLinkageTable opts file
  | DisplayELF ELFEHFrame -> dumpEHFrame hdl file
  | DisplayELF ELFGccExceptTbl -> dumpGccExceptTable hdl file
  | DisplayELF ELFNotes -> dumpNotes hdl file
  | DisplayPE PEImports -> dumpImports opts file
  | DisplayPE PEExports -> dumpExports opts file
  | DisplayPE PEOptionalHeader -> dumpOptionalHeader opts file
  | DisplayPE PECLRHeader -> dumpCLRHeader opts file
  | DisplayPE PEDependencies -> dumpDependencies opts file
  | DisplayMach MachArchiveHdr -> dumpArchiveHeader opts file
  | DisplayMach MachUniversalHdr -> dumpUnivHeader opts file
  | DisplayMach MachLoadCmds -> dumpLoadCommands opts file
  | DisplayMach MachSharedLibs -> dumpSharedLibs opts file

let private dumpFile (opts: FileViewerOpts) (filePath: string) =
  let hdl = BinHandle(filePath, opts.ISA, opts.BaseAddress)
  let file = hdl.File
  printFileName file.Path
  if opts.DisplayItems.Count = 0 then printBasic file
  elif opts.DisplayItems.Contains DisplayAll then printAll opts hdl file
  else opts.DisplayItems |> Seq.iter (printSelectively hdl opts file)

let [<Literal>] private ToolName = "fileview"

let [<Literal>] private UsageTail = "<binary file(s)>"

let private dump files opts =
  CmdOpts.sanitizeRestArgs files
  match files with
  | [] ->
    eprintsn "File(s) must be given."
    CmdOpts.printUsage ToolName UsageTail FileViewerOpts.Spec
  | files ->
#if DEBUG
    let sw = System.Diagnostics.Stopwatch.StartNew()
#endif
    try files |> List.iter (dumpFile opts)
    finally flush ()
#if DEBUG
    sw.Stop()
    let sec = sw.Elapsed.TotalSeconds
    System.Console.Error.WriteLine $"Total time: {sec} sec."
#endif

[<EntryPoint>]
let main args =
  let opts = FileViewerOpts.Default()
  CmdOpts.parseAndRun dump ToolName UsageTail FileViewerOpts.Spec opts args
