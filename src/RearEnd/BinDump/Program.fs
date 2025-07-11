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

module B2R2.RearEnd.BinDump.Program

open System
open B2R2
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile
open B2R2.RearEnd.Utils
open B2R2.RearEnd.BinDump.DisasmLiftHelper

let [<Literal>] private ToolName = "bindump"
let [<Literal>] private UsageTail = "<binary file(s) | -s hexstring>"

let private printFileName (filepath: string) =
  out.PrintLine (String.wrapSqrdBracket filepath)
  out.PrintLine ()

let private getTableConfig (isa: ISA) isLift =
  if isLift then [ LeftAligned 10 ]
  else
    let addrWidth = WordSize.toByteWidth isa.WordSize * 2
    let binaryWidth =
      match isa with
      | Intel -> 36
      | _ -> 16
    [ LeftAligned addrWidth; LeftAligned binaryWidth; LeftAligned 10 ]

let private isARM32 (hdl: BinHandle) =
  match hdl.File.ISA with
  | ARM32 -> true
  | _ -> false

let private makeCodePrinter hdl cfg (opts: BinDumpOpts) =
  let opti = getOptimizer opts
  if isARM32 hdl then
    if opts.ShowLowUIR then
      ContextSensitiveCodeIRPrinter (hdl, cfg, opti) :> BinPrinter
    else
      let showSymb, showColor = opts.ShowSymbols, opts.ShowColor
      ContextSensitiveCodeDisasmPrinter (hdl, cfg, showSymb, showColor)
      :> BinPrinter
  else
    if opts.ShowLowUIR then BinCodeIRPrinter (hdl, cfg, opti) :> BinPrinter
    else
      let showSymb, showColor = opts.ShowSymbols, opts.ShowColor
      let printer =
        BinCodeDisasmPrinter (hdl, cfg, showSymb, showColor) :> BinPrinter
      printer.LiftingUnit.SetDisassemblySyntax opts.DisassemblySyntax
      printer

let private makeTablePrinter hdl cfg (opts: BinDumpOpts) =
  let opti = getOptimizer opts
  if isARM32 hdl then
    if opts.ShowLowUIR then
      ContextSensitiveTableIRPrinter (hdl, cfg, opti) :> BinPrinter
    else
      ContextSensitiveTableDisasmPrinter (hdl, cfg) :> BinPrinter
  else
    if opts.ShowLowUIR then BinTableIRPrinter (hdl, cfg, opti) :> BinPrinter
    else BinTableDisasmPrinter (hdl, cfg) :> BinPrinter

let private dumpRawBinary (hdl: BinHandle) (opts: BinDumpOpts) cfg =
  let ptr = hdl.File.GetBoundedPointer hdl.File.BaseAddress
  let prn = makeCodePrinter hdl cfg opts
  prn.Print ptr
  out.PrintLine ()

let printHexdump (opts: BinDumpOpts) (hdl: BinHandle) ptr =
  let bytes = hdl.ReadBytes (ptr = ptr, nBytes = ptr.MaxOffset - ptr.Offset + 1)
  let chunkSz = if opts.ShowWide then 32 else 16
  HexDumper.dump chunkSz hdl.File.ISA.WordSize opts.ShowColor ptr.Addr bytes
  |> Array.iter out.PrintLine

let private hasNoContent (file: IBinFile) secName =
  match file with
  | :? ELFBinFile as file ->
    match file.TryFindSection secName with
    | Some section -> section.SecType = ELF.SectionType.SHT_NOBITS
    | None -> true
  | _ -> false

let dumpHex (hdl: BinHandle) (opts: BinDumpOpts) ptr secName =
  out.PrintSectionTitle (String.wrapParen secName)
  if hasNoContent hdl.File secName then
    out.PrintTwoCols "" "NOBITS section."
  else printHexdump opts hdl ptr
  out.PrintLine ()

let private createBinHandleFromPath (opts: BinDumpOpts) filePath =
  BinHandle (filePath, opts.ISA, opts.BaseAddress)

let private isRawBinary (hdl: BinHandle) =
  match hdl.File.Format with
  | FileFormat.ELFBinary
  | FileFormat.MachBinary
  | FileFormat.PEBinary
  | FileFormat.WasmBinary
  | FileFormat.PythonBinary -> false
  | _ -> true

let private printCodeOrTable (printer: BinPrinter) ptr =
  printer.Print ptr
  out.PrintLine ()

let private dumpOneSection (prn: BinPrinter) name ptr =
  out.PrintSectionTitle (String.wrapParen name)
  printCodeOrTable prn ptr

let private dumpELFSection hdl opts elf tableprn codeprn sec =
  if (sec: ELF.SectionHeader).SecSize > 0UL then
    let name = sec.SecName
    let ptr = (hdl: BinHandle).File.GetSectionPointer name
    if (elf: ELFBinFile).IsPLT sec then dumpOneSection tableprn name ptr
    elif elf.HasCode sec then dumpOneSection codeprn name ptr
    elif (opts: BinDumpOpts).OnlyDisasm then dumpOneSection codeprn name ptr
    else dumpHex hdl opts ptr name
  else ()

let private dumpPESection (hdl: BinHandle) opts pe _tableprn codeprn sec =
  let name = (sec: Reflection.PortableExecutable.SectionHeader).Name
  let ptr = (hdl: BinHandle).File.GetSectionPointer name
  if (pe: PEBinFile).HasCode sec then dumpOneSection codeprn name ptr
  elif (opts: BinDumpOpts).OnlyDisasm then dumpOneSection codeprn name ptr
  else dumpHex hdl opts ptr name

let private dumpMachSection (hdl: BinHandle) opts mach tableprn codeprn sec =
  let name = (sec: Mach.Section).SecName
  let ptr = (hdl: BinHandle).File.GetSectionPointer name
  if (mach: MachBinFile).IsPLT sec then dumpOneSection tableprn name ptr
  elif mach.HasCode sec then dumpOneSection codeprn name ptr
  elif (opts: BinDumpOpts).OnlyDisasm then dumpOneSection codeprn name ptr
  else dumpHex hdl opts ptr name

let private dumpOneSectionOfName (hdl: BinHandle) opts codeprn tableprn name =
  match hdl.File with
  | :? ELFBinFile as elf ->
    elf.TryFindSection name
    |> function
      | Some sec -> dumpELFSection hdl opts elf tableprn codeprn sec
      | None -> ()
  | :? PEBinFile as pe ->
    pe.SectionHeaders |> Array.tryFind (fun sec -> sec.Name = name)
    |> function
      | Some sec -> dumpPESection hdl opts pe tableprn codeprn sec
      | None -> ()
  | :? MachBinFile as mach ->
    mach.Sections |> Array.tryFind (fun sec -> sec.SecName = name)
    |> function
      | Some sec -> dumpMachSection hdl opts mach tableprn codeprn sec
      | None -> ()
  | _ -> Terminator.futureFeature ()

let private dumpRegularFile (hdl: BinHandle) (opts: BinDumpOpts) cfg =
  let codeprn = makeCodePrinter hdl cfg opts
  let tableprn = makeTablePrinter hdl cfg opts
  opts.ShowSymbols <- true
  match opts.InputSecName with
  | Some secName -> dumpOneSectionOfName hdl opts codeprn tableprn secName
  | None ->
    match hdl.File with
    | :? ELFBinFile as elf ->
      for sec in elf.SectionHeaders do
        dumpELFSection hdl opts elf tableprn codeprn sec
    | :? PEBinFile as pe ->
      for sec in pe.SectionHeaders do
        dumpPESection hdl opts pe tableprn codeprn sec
    | :? MachBinFile as mach ->
      for sec in mach.Sections do
        dumpMachSection hdl opts mach tableprn codeprn sec
    | _ -> Terminator.futureFeature ()

let dumpFile (opts: BinDumpOpts) filepath =
  opts.ShowAddress <- true
  let hdl = createBinHandleFromPath opts filepath
  let cfg = getTableConfig hdl.File.ISA opts.ShowLowUIR
  printFileName hdl.File.Path
  if isRawBinary hdl then dumpRawBinary hdl opts cfg
  else dumpRegularFile hdl opts cfg

let dumpFileMode files (opts: BinDumpOpts) =
  match List.partition IO.File.Exists files with
  | [], [] ->
    Printer.PrintErrorToConsole "File(s) must be given."
    CmdOpts.PrintUsage ToolName UsageTail Cmd.spec
  | files, [] -> files |> List.iter (dumpFile opts)
  | _, errs ->
    Printer.PrintErrorToConsole ("File(s) " + errs.ToString() + " not found!")

let private assertBinaryLength isa isThumb hexstr =
  let multiplier = getInstructionAlignment isa isThumb
  if (Array.length hexstr) % multiplier = 0 then ()
  else
    Printer.PrintErrorToConsole <|
      "The hex string length must be multiple of " + multiplier.ToString ()
    exit 1

let dumpHexStringMode (opts: BinDumpOpts) =
  let isa, isThumb = opts.ISA, opts.ThumbMode
  let hdl = BinHandle (opts.InputHexStr, isa, opts.BaseAddress, false)
  let cfg = getTableConfig hdl.File.ISA opts.ShowLowUIR
  assertBinaryLength isa isThumb opts.InputHexStr
  opts.ShowColor <- true
  let printer = makeCodePrinter hdl cfg opts
  printer.ModeSwitch.IsThumb <- isThumb
  let baseAddr = defaultArg opts.BaseAddress 0UL
  let len = opts.InputHexStr.Length
  let ptr = BinFilePointer (baseAddr, baseAddr + uint64 len - 1UL, 0, len - 1)
  printer.Print ptr
  out.PrintLine ()

let private dump files (opts: BinDumpOpts) =
#if DEBUG
  let sw = Diagnostics.Stopwatch.StartNew ()
#endif
  CmdOpts.SanitizeRestArgs files
  try
    if Array.isEmpty opts.InputHexStr then dumpFileMode files opts
    else dumpHexStringMode opts
  finally
    out.Flush ()
#if DEBUG
  sw.Stop ()
  eprintfn "Total dump time: %f sec." sw.Elapsed.TotalSeconds
#endif

[<EntryPoint>]
let main args =
  let opts = BinDumpOpts ()
  CmdOpts.ParseAndRun dump ToolName UsageTail Cmd.spec opts args
