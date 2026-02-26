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

module B2R2.RearEnd.BinDisasm.Program

open System
open B2R2
open B2R2.Logging
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinLifter
open B2R2.RearEnd.Utils

let [<Literal>] private ToolName = "disasm"

let [<Literal>] private UsageTail = "<binary file(s) | -s hexstring>"

let private printFileName (filepath: string) =
  printsn <| String.wrapSqrdBracket filepath
  printsn ""

let private computeBinaryWidth isa =
  match isa with
  | Intel -> 36
  | _ -> 16

let private initTableConfig (isa: ISA) isLift =
  if isLift then
    setTableColumnFormats [| LeftAligned 10 |]
  else
    let addrWidth = WordSize.toByteWidth isa.WordSize * 2
    let binaryWidth = computeBinaryWidth isa
    setTableColumnFormats
      [| LeftAligned addrWidth; LeftAligned binaryWidth; LeftAligned 10 |]

let private getOptimizer (opts: BinDisasmOpts) =
  if opts.DoOptimization then LocalOptimizer.Optimize
  else id

let private makeCodeDumper hdl (opts: BinDisasmOpts) =
  let mode =
    if opts.ShowLowUIR then LowUIR(getOptimizer opts)
    else Disassembly(opts.DisassemblySyntax)
  BinCodeDumper(hdl, false, opts.ShowSymbols, opts.ShowColor, mode)
  :> IBinDumper

let private makeTableDumper hdl (opts: BinDisasmOpts) =
  let mode =
    if opts.ShowLowUIR then LowUIR(getOptimizer opts)
    else Disassembly(opts.DisassemblySyntax)
  BinCodeDumper(hdl, true, true, opts.ShowColor, mode)
  :> IBinDumper

let private dumpRawBinary (hdl: BinHandle) (opts: BinDisasmOpts) =
  let ptr = hdl.File.GetBoundedPointer hdl.File.BaseAddress
  let dumper = makeCodeDumper hdl opts
  dumper.Dump ptr
  printsn ""

let private dumpHex (opts: BinDisasmOpts) (hdl: BinHandle) ptr =
  let bytes = hdl.ReadBytes(ptr = ptr, nBytes = ptr.MaxOffset - ptr.Offset + 1)
  let chunkSz = if opts.ShowWide then 32 else 16
  HexDump.makeLines chunkSz hdl.File.ISA.WordSize opts.ShowColor ptr.Addr bytes
  |> Array.iter printon

let private hasNoContent (file: IBinFile) secName =
  match file with
  | :? ELFBinFile as file ->
    match file.TryFindSection secName with
    | Some section -> section.SecType = ELF.SectionType.SHT_NOBITS
    | None -> true
  | _ -> false

let private dumpData (hdl: BinHandle) (opts: BinDisasmOpts) ptr secName =
  printSectionTitle <| String.wrapParen secName
  if hasNoContent hdl.File secName then
    resetToDefaultTwoColumnConfig ()
    printsr [| ""; "NOBITS section." |]
  else
    dumpHex opts hdl ptr
  printsn ""

let private isRawBinary (hdl: BinHandle) =
  match hdl.File.Format with
  | FileFormat.ELFBinary
  | FileFormat.MachBinary
  | FileFormat.PEBinary
  | FileFormat.WasmBinary
  | FileFormat.PythonBinary -> false
  | _ -> true

let private dumpOneSection (dumper: IBinDumper) name ptr =
  printSectionTitle <| String.wrapParen name
  dumper.Dump ptr
  printsn ""

let private dumpELFSection hdl opts elf tableprn codeprn sec =
  if (sec: ELF.SectionHeader).SecSize > 0UL then
    let name = sec.SecName
    let ptr = (hdl: BinHandle).File.GetSectionPointer name
    if (elf: ELFBinFile).IsPLT sec then dumpOneSection tableprn name ptr
    elif elf.HasCode sec then dumpOneSection codeprn name ptr
    elif (opts: BinDisasmOpts).OnlyDisasm then dumpOneSection codeprn name ptr
    else dumpData hdl opts ptr name
  else ()

let private dumpPESection (hdl: BinHandle) opts pe _tableprn codeprn sec =
  let name = (sec: Reflection.PortableExecutable.SectionHeader).Name
  let ptr = (hdl: BinHandle).File.GetSectionPointer name
  if (pe: PEBinFile).HasCode sec then dumpOneSection codeprn name ptr
  elif (opts: BinDisasmOpts).OnlyDisasm then dumpOneSection codeprn name ptr
  else dumpData hdl opts ptr name

let private dumpMachSection (hdl: BinHandle) opts mach tableprn codeprn sec =
  let name = (sec: Mach.Section).SecName
  let ptr = (hdl: BinHandle).File.GetSectionPointer name
  if (mach: MachBinFile).IsPLT sec then dumpOneSection tableprn name ptr
  elif mach.HasCode sec then dumpOneSection codeprn name ptr
  elif (opts: BinDisasmOpts).OnlyDisasm then dumpOneSection codeprn name ptr
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

let private dumpAllSections (hdl: BinHandle) opts codeprn tableprn =
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

let private dumpRegularFile (hdl: BinHandle) (opts: BinDisasmOpts) =
  let codeprn = makeCodeDumper hdl opts
  let tableprn = makeTableDumper hdl opts
  let opts = { opts with ShowSymbols = true }
  match opts.InputSecName with
  | Some secName ->
    dumpOneSectionOfName hdl opts codeprn tableprn secName
  | None ->
    dumpAllSections hdl opts codeprn tableprn

let private dumpFile (opts: BinDisasmOpts) filePath =
  let opts = { opts with ShowAddress = true }
  let hdl = BinHandle(filePath, opts.ISA, opts.BaseAddress)
  initTableConfig hdl.File.ISA opts.ShowLowUIR
  printFileName hdl.File.Path
  if isRawBinary hdl then dumpRawBinary hdl opts
  else dumpRegularFile hdl opts

let private dumpFiles files opts =
  match List.partition IO.File.Exists files with
  | [], [] ->
    eprintsn "File(s) must be given."
    CmdOpts.printUsage ToolName UsageTail BinDisasmOpts.Spec
  | files, [] ->
    Log.EnableCaching()
    files |> List.iter (dumpFile opts)
    Log.DisableCaching()
  | _, errs ->
    eprintsn <| "File(s) " + errs.ToString() + " not found!"

let private validateHexStringLength (hdl: BinHandle) hexstr =
  let liftingUnit = hdl.NewLiftingUnit()
  let alignment = liftingUnit.InstructionAlignment
  if (Array.length hexstr) % alignment = 0 then
    ()
  else
    eprintsn $"The hex string length must be multiple of {alignment}"
    exit 1

let private prepareHexStringDump (opts: BinDisasmOpts) =
  let hex, isa = opts.InputHexStr, opts.ISA
  let hdl = BinHandle(hex, isa, opts.BaseAddress, detectFormat = false)
  initTableConfig hdl.File.ISA opts.ShowLowUIR
  validateHexStringLength hdl opts.InputHexStr
  hdl

let private dumpHexString (opts: BinDisasmOpts) =
  let hdl = prepareHexStringDump opts
  let dumper = makeCodeDumper hdl { opts with ShowColor = true }
  let baseAddr = defaultArg opts.BaseAddress 0UL
  let len = opts.InputHexStr.Length
  let ptr = BinFilePointer(baseAddr, baseAddr + uint64 len - 1UL, 0, len - 1)
  dumper.ModeSwitch.IsThumb <- opts.ThumbMode
  dumper.Dump ptr
  printsn ""

let private disasm files (opts: BinDisasmOpts) =
  CmdOpts.sanitizeRestArgs files
#if DEBUG
  let sw = Diagnostics.Stopwatch.StartNew()
#endif
  try
    if Array.isEmpty opts.InputHexStr then dumpFiles files opts
    else dumpHexString opts
  finally
    Log.Out.Flush()
#if DEBUG
  sw.Stop()
  Console.Error.WriteLine $"Total dump time: {sw.Elapsed.TotalSeconds} sec."
#endif

[<EntryPoint>]
let main args =
  let opts = BinDisasmOpts.Default
  CmdOpts.parseAndRun disasm ToolName UsageTail BinDisasmOpts.Spec opts args
