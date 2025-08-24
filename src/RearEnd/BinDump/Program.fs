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
open B2R2.FrontEnd.BinLifter
open B2R2.RearEnd.Utils

let [<Literal>] private ToolName = "bindump"

let [<Literal>] private UsageTail = "<binary file(s) | -s hexstring>"

let private printFileName (filepath: string) =
  Terminal.COut <=/ String.wrapSqrdBracket filepath
  Terminal.COut.PrintLine()

let private getTableConfig (isa: ISA) isLift =
  if isLift then
    { Indentation = 0
      ColumnGap = 1
      Columns = [ LeftAligned 10 ] }
  else
    let addrWidth = WordSize.toByteWidth isa.WordSize * 2
    let binaryWidth =
      match isa with
      | Intel -> 36
      | _ -> 16
    { Indentation = 0
      ColumnGap = 1
      Columns = [ LeftAligned addrWidth
                  LeftAligned binaryWidth
                  LeftAligned 10 ] }

let private getOptimizer (opts: BinDumpOpts) =
  if opts.DoOptimization then LocalOptimizer.Optimize
  else id

let private makeCodeDumper hdl cfg (opts: BinDumpOpts) =
  let mode =
    if opts.ShowLowUIR then LowUIR(getOptimizer opts)
    else Disassembly(opts.DisassemblySyntax)
  BinCodeDumper(hdl, cfg, false, opts.ShowSymbols, opts.ShowColor, mode)
  :> IBinDumper

let private makeTableDumper hdl cfg (opts: BinDumpOpts) =
  let mode =
    if opts.ShowLowUIR then LowUIR(getOptimizer opts)
    else Disassembly(opts.DisassemblySyntax)
  BinCodeDumper(hdl, cfg, true, true, opts.ShowColor, mode)
  :> IBinDumper

let private dumpRawBinary (hdl: BinHandle) (opts: BinDumpOpts) cfg =
  let ptr = hdl.File.GetBoundedPointer hdl.File.BaseAddress
  let dumper = makeCodeDumper hdl cfg opts
  dumper.Dump ptr
  Terminal.COut.PrintLine()

let dumpHex (opts: BinDumpOpts) (hdl: BinHandle) ptr =
  let bytes = hdl.ReadBytes(ptr = ptr, nBytes = ptr.MaxOffset - ptr.Offset + 1)
  let chunkSz = if opts.ShowWide then 32 else 16
  HexDump.render chunkSz hdl.File.ISA.WordSize opts.ShowColor ptr.Addr bytes
  |> Array.iter Terminal.COut.PrintLine

let private hasNoContent (file: IBinFile) secName =
  match file with
  | :? ELFBinFile as file ->
    match file.TryFindSection secName with
    | Some section -> section.SecType = ELF.SectionType.SHT_NOBITS
    | None -> true
  | _ -> false

let dumpData (hdl: BinHandle) (opts: BinDumpOpts) ptr secName =
  Terminal.COut.PrintSectionTitle(String.wrapParen secName)
  if hasNoContent hdl.File secName then
    Terminal.COut.SetTableConfig TableConfig.DefaultTwoColumn
    Terminal.COut.PrintRow([ ""; "NOBITS section." ])
  else dumpHex opts hdl ptr
  Terminal.COut.PrintLine()

let private isRawBinary (hdl: BinHandle) =
  match hdl.File.Format with
  | FileFormat.ELFBinary
  | FileFormat.MachBinary
  | FileFormat.PEBinary
  | FileFormat.WasmBinary
  | FileFormat.PythonBinary -> false
  | _ -> true

let private dumpOneSection (dumper: IBinDumper) name ptr =
  Terminal.COut.PrintSectionTitle(String.wrapParen name)
  dumper.Dump ptr
  Terminal.COut.PrintLine()

let private dumpELFSection hdl opts elf tableprn codeprn sec =
  if (sec: ELF.SectionHeader).SecSize > 0UL then
    let name = sec.SecName
    let ptr = (hdl: BinHandle).File.GetSectionPointer name
    if (elf: ELFBinFile).IsPLT sec then dumpOneSection tableprn name ptr
    elif elf.HasCode sec then dumpOneSection codeprn name ptr
    elif (opts: BinDumpOpts).OnlyDisasm then dumpOneSection codeprn name ptr
    else dumpData hdl opts ptr name
  else ()

let private dumpPESection (hdl: BinHandle) opts pe _tableprn codeprn sec =
  let name = (sec: Reflection.PortableExecutable.SectionHeader).Name
  let ptr = (hdl: BinHandle).File.GetSectionPointer name
  if (pe: PEBinFile).HasCode sec then dumpOneSection codeprn name ptr
  elif (opts: BinDumpOpts).OnlyDisasm then dumpOneSection codeprn name ptr
  else dumpData hdl opts ptr name

let private dumpMachSection (hdl: BinHandle) opts mach tableprn codeprn sec =
  let name = (sec: Mach.Section).SecName
  let ptr = (hdl: BinHandle).File.GetSectionPointer name
  if (mach: MachBinFile).IsPLT sec then dumpOneSection tableprn name ptr
  elif mach.HasCode sec then dumpOneSection codeprn name ptr
  elif (opts: BinDumpOpts).OnlyDisasm then dumpOneSection codeprn name ptr
  else dumpData hdl opts ptr name

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
  let codeprn = makeCodeDumper hdl cfg opts
  let tableprn = makeTableDumper hdl cfg opts
  let opts = { opts with ShowSymbols = true }
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

let dumpFile (opts: BinDumpOpts) filePath =
  let opts = { opts with ShowAddress = true }
  let hdl = BinHandle(filePath, opts.ISA, opts.BaseAddress)
  let cfg = getTableConfig hdl.File.ISA opts.ShowLowUIR
  printFileName hdl.File.Path
  if isRawBinary hdl then dumpRawBinary hdl opts cfg
  else dumpRegularFile hdl opts cfg

let private dumpFiles files opts =
  match List.partition IO.File.Exists files with
  | [], [] ->
    Terminal.Out <=? "File(s) must be given."
    CmdOpts.printUsage ToolName UsageTail BinDumpOpts.Spec
  | files, [] ->
    files |> List.iter (dumpFile opts)
  | _, errs ->
    Terminal.Out <=? "File(s) " + errs.ToString() + " not found!"

let private validateHexStringLength (liftingUnit: LiftingUnit) hexstr =
  let alignment = liftingUnit.InstructionAlignment
  if (Array.length hexstr) % alignment = 0 then ()
  else
    Terminal.Out <=? $"The hex string length must be multiple of {alignment}"
    exit 1

let private dumpDataString (opts: BinDumpOpts) =
  let hex, isa, isThumb = opts.InputHexStr, opts.ISA, opts.ThumbMode
  let hdl = BinHandle(hex, isa, opts.BaseAddress, detectFormat = false)
  let liftingUnit = hdl.NewLiftingUnit()
  let cfg = getTableConfig hdl.File.ISA opts.ShowLowUIR
  validateHexStringLength liftingUnit opts.InputHexStr
  let opts = { opts with ShowColor = true }
  let dumper = makeCodeDumper hdl cfg opts
  dumper.ModeSwitch.IsThumb <- isThumb
  let baseAddr = defaultArg opts.BaseAddress 0UL
  let len = opts.InputHexStr.Length
  let ptr = BinFilePointer(baseAddr, baseAddr + uint64 len - 1UL, 0, len - 1)
  dumper.Dump ptr
  Terminal.COut.PrintLine()

let private dumpMain files (opts: BinDumpOpts) =
#if DEBUG
  let sw = Diagnostics.Stopwatch.StartNew()
#endif
  CmdOpts.sanitizeRestArgs files
  try
    if Array.isEmpty opts.InputHexStr then dumpFiles files opts
    else dumpDataString opts
  finally
    Terminal.COut.Flush()
#if DEBUG
  sw.Stop()
  Terminal.Out <=/ $"Total dump time: {sw.Elapsed.TotalSeconds} sec."
#endif

[<EntryPoint>]
let main args =
  let opts = BinDumpOpts.Default
  CmdOpts.parseAndRun dumpMain ToolName UsageTail BinDumpOpts.Spec opts args
