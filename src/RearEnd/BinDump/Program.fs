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

open B2R2
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinInterface
open B2R2.RearEnd
open B2R2.RearEnd.BinDump.DisasmLiftHelper

let [<Literal>] private toolName = "bindump"
let [<Literal>] private usageTail = "<binary file(s) | -s hexstring>"

let private printFileName (filepath: string) =
  Printer.println (StringUtils.wrapSqrdBracket filepath)
  Printer.println ()

let private getTableConfig hdl isLift =
  if isLift then [ LeftAligned 10 ]
  else
    let addrWidth = WordSize.toByteWidth hdl.ISA.WordSize * 2
    let binaryWidth =
      match hdl.ISA.Arch with
      | Arch.IntelX86 | Arch.IntelX64 -> 36
      | _ -> 16
    [ LeftAligned addrWidth; LeftAligned binaryWidth; LeftAligned 10 ]

let private dumpRawBinary (hdl: BinHandle) (opts: BinDumpOpts) cfg =
  let bp = hdl.FileInfo.ToBinaryPointer hdl.FileInfo.BaseAddr
  let optimizer = getOptimizer opts
  if opts.ShowLowUIR then printBlkLowUIR hdl cfg optimizer bp
  else printBlkDisasm hdl cfg opts bp None
  Printer.println ()

let printHexdump (opts: BinDumpOpts) sec hdl =
  let bp = BinaryPointer.OfSection sec
  let bytes = BinHandle.ReadBytes (hdl, bp=bp, nBytes=int sec.Size)
  let chunkSize = if opts.ShowWide then 32 else 16
  HexDumper.dump chunkSize hdl.FileInfo.WordSize opts.ShowColor bp.Addr bytes
  |> Array.iter Printer.println

let private hasNoContent (sec: Section) (fi: FileInfo) =
  match fi with
  | :? ELFFileInfo as fi ->
    match fi.ELF.SecInfo.SecByName.TryFind sec.Name with
    | Some section -> section.SecType = ELF.SectionType.SHTNoBits
    | None -> true
  | _ -> false

let dumpHex (opts: BinDumpOpts) (sec: Section) hdl =
  if hasNoContent sec hdl.FileInfo then
    Printer.printTwoCols "" "NOBITS section."
  else printHexdump opts sec hdl
  Printer.println ()

let private createBinHandleFromPath (opts: BinDumpOpts) filepath forceRawBin =
  BinHandle.Init (
    opts.ISA,
    opts.ArchOperationMode,
    (if forceRawBin then false else opts.AutoDetect),
    opts.BaseAddress,
    fileName=filepath)

let private isRawBinary hdl =
  match hdl.FileInfo.FileFormat with
  | FileFormat.ELFBinary
  | FileFormat.MachBinary
  | FileFormat.PEBinary -> false
  | _ -> true

let private irDumper hdl _opts cfg optimizer _funcs sec =
  printBlkLowUIR hdl cfg optimizer (BinaryPointer.OfSection sec)
  Printer.println ()

let private disasDumper hdl opts cfg _optimizer funcs sec =
  printBlkDisasm hdl cfg opts (BinaryPointer.OfSection sec) funcs
  Printer.println ()

let private getTblEntrySize hdl =
  match hdl.FileInfo.FileFormat, hdl.ISA.Arch with
  | FileFormat.ELFBinary, Architecture.IntelX86
  | FileFormat.ELFBinary, Architecture.IntelX64 -> 16
  | FileFormat.ELFBinary, Architecture.ARMv7
  | FileFormat.ELFBinary, Architecture.AARCH32 -> 12
  | _ -> Utils.futureFeature ()

let private tblIter (sec: Section) entrySize fn =
  Printer.println (StringUtils.wrapAngleBracket sec.Name)
  let rec loop bp =
    if BinaryPointer.IsValid bp then
      fn (BinaryPointer (bp.Addr, bp.Offset, bp.Offset + entrySize))
      loop (BinaryPointer.Advance bp entrySize)
    else ()
  loop (BinaryPointer.OfSection sec)

let private irTblDumper hdl _opts cfg optimizer (sec: Section) =
  let entrySize = getTblEntrySize hdl
  tblIter sec entrySize (fun range -> printBlkLowUIR hdl cfg optimizer range)

let private disasTblDumper hdl opts cfg _optimizer (sec: Section) =
  let entrySize = getTblEntrySize hdl
  let funcs = createLinkageTableSymbolDic hdl |> Some
  tblIter sec entrySize (fun range -> printBlkDisasm hdl cfg opts range funcs)

let private printTitle action name =
  Printer.printSectionTitle (action + " of section " + name + ":")

let private dumpSections hdl (opts: BinDumpOpts) (sections: seq<Section>) cfg =
  let optimizer = getOptimizer opts
  let struct (codeDump, tblDump, action) =
    if opts.ShowLowUIR then struct (irDumper, irTblDumper, "LowUIR")
    else struct (disasDumper, disasTblDumper, "Disassembly")
  let funcs = Some (createFuncSymbolDic hdl)
  sections
  |> Seq.iter (fun s ->
    if s.Size > 0UL then
      match s.Kind with
      | SectionKind.ExecutableSection ->
        printTitle action s.Name
        codeDump hdl opts cfg optimizer funcs s
      | SectionKind.LinkageTableSection ->
        printTitle action s.Name
        tblDump hdl opts cfg optimizer s
      | _ ->
        printTitle "Contents" s.Name
        dumpHex opts s hdl
    else ())

let private dumpRegularFile hdl (opts: BinDumpOpts) cfg =
  match opts.InputSecName with
  | Some secname ->
    dumpSections hdl opts (hdl.FileInfo.GetSections (secname)) cfg
  | None ->
    dumpSections hdl opts (hdl.FileInfo.GetSections ()) cfg

let dumpFile (opts: BinDumpOpts) filepath =
  opts.ShowAddress <- true
  let hdl = createBinHandleFromPath opts filepath false
  printFileName hdl.FileInfo.FilePath
  if isRawBinary hdl then
    let hdl = createBinHandleFromPath opts filepath true
    let cfg = getTableConfig hdl opts.ShowLowUIR
    dumpRawBinary hdl opts cfg
  else
    let cfg = getTableConfig hdl opts.ShowLowUIR
    dumpRegularFile hdl opts cfg

let dumpFileMode files (opts: BinDumpOpts) =
  match List.partition System.IO.File.Exists files with
  | [], [] ->
    Printer.printError "File(s) must be given."
    CmdOpts.PrintUsage toolName usageTail Cmd.spec
  | files, [] -> files |> List.iter (dumpFile opts)
  | _, errs -> Printer.printError ("File(s) " + errs.ToString() + " not found!")

let private assertBinaryLength hdl hexstr =
  let multiplier = getInstructionAlignment hdl
  if (Array.length hexstr) % multiplier = 0 then ()
  else
    Printer.printError <|
      "The hex string length must be multiple of " + multiplier.ToString ()
    exit 1

let dumpHexStringMode (opts: BinDumpOpts) =
  opts.ShowSymbols <- false
  opts.ShowColor <- true
  let hdl = BinHandle.Init (opts.ISA,
                            opts.ArchOperationMode,
                            false,
                            opts.BaseAddress,
                            opts.InputHexStr)
  let cfg = getTableConfig hdl opts.ShowLowUIR
  let optimizer = getOptimizer opts
  assertBinaryLength hdl opts.InputHexStr
  let bp = BinaryPointer (0UL, 0, opts.InputHexStr.Length)
  if opts.ShowLowUIR then printBlkLowUIR hdl cfg optimizer bp
  else printBlkDisasm hdl cfg opts bp None
  Printer.println ()

let private dump files (opts: BinDumpOpts) =
#if DEBUG
  let sw = System.Diagnostics.Stopwatch.StartNew ()
#endif
  CmdOpts.SanitizeRestArgs files
  if Array.isEmpty opts.InputHexStr then dumpFileMode files opts
  else dumpHexStringMode opts
#if DEBUG
  sw.Stop ()
  eprintfn "Total dump time: %f sec." sw.Elapsed.TotalSeconds
#endif

[<EntryPoint>]
let main args =
  let opts = BinDumpOpts ()
  CmdOpts.ParseAndRun dump toolName usageTail Cmd.spec opts args
