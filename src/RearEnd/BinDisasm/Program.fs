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
  printsn <| String.wrapSquareBracket filepath
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
  if opts.DoOptimization then LocalOptimizer.Optimize else id

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
  let bytes = hdl.ReadBytes(ptr = ptr, nBytes = ptr.ReadableAmount)
  let chunkSz = if opts.ShowWide then 32 else 16
  HexDump.makeLines chunkSz hdl.ISA.WordSize opts.ShowColor ptr.Addr bytes
  |> Array.iter printon

let private dumpData hdl (opts: BinDisasmOpts) ptr (sec: BinSection) =
  printSectionTitle <| String.wrapParen sec.Name
  if sec.Kind = UninitializedDataSection then
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

(* A .pyc has no sections: it is a marshalled tree of code objects, and the
   thing that corresponds to a section is one code object's own co_code. Walk
   the tree so each is dumped under its own qualified name, in address order.
   B2R2 addresses a code object by the file offset of those bytes, so address
   and offset are the same number here. *)
let private pythonCodeObjects (file: PythonBinFile) =
  let acc = ResizeArray<string * Addr * uint64>()
  let rec collect obj =
    match obj with
    | Python.PyREF(_, o) ->
      collect o
    | Python.PyCode co ->
      let addr, code = co.Code
      match code with
      | Python.PyString bs when bs.Length > 0 ->
        acc.Add(co.QualName, addr, uint64 bs.Length)
      | _ ->
        ()
      match co.Consts with
      | Python.PyTuple objs
      | Python.PyREF(_, Python.PyTuple objs) -> Array.iter collect objs
      | _ -> ()
    | _ ->
      ()
  collect file.CodeObj
  acc |> Seq.sortBy (fun (_, addr, _) -> addr) |> Seq.toArray

let private dumpPythonCodeObjects (hdl: BinHandle) (codeprn: IBinDumper) =
  let file = hdl.File :?> PythonBinFile
  for name, addr, len in pythonCodeObjects file do
    let ptr =
      BinFilePointer.CreateFileBacked(addr,
                                      addr + len - 1UL,
                                      int addr,
                                      int (addr + len) - 1)
    dumpOneSection codeprn $"code object {name}" ptr

let private dumpSection hdl
                        (opts: BinDisasmOpts)
                        codeprn
                        tableprn
                        (sec: BinSection) =
  if sec.Size > 0UL then
    let ptr = BinFileOps.getSectionPointer (hdl: BinHandle).File sec.Name
    match sec.Kind with
    | DynamicLinkageSection ->
      dumpOneSection tableprn sec.Name ptr
    | _ when sec.Permission.HasFlag Permission.Executable ->
      dumpOneSection codeprn sec.Name ptr
    | _ when opts.OnlyDisasm ->
      dumpOneSection codeprn sec.Name ptr
    | _ ->
      dumpData hdl opts ptr sec
  else
    ()

/// Section dumping is supported only for formats that expose a section view.
let private hasDumpableSections (hdl: BinHandle) =
  match hdl.File.Format with
  | FileFormat.ELFBinary
  | FileFormat.PEBinary
  | FileFormat.MachBinary -> true
  | _ -> false

let private dumpOneSectionOfName (hdl: BinHandle) opts codeprn tableprn name =
  if hdl.File.Format = FileFormat.PythonBinary then
    pythonCodeObjects (hdl.File :?> PythonBinFile)
    |> Array.filter (fun (n, _, _) -> n = name)
    |> Array.iter (fun (n, addr, len) ->
      let ptr =
        BinFilePointer.CreateFileBacked(addr,
                                        addr + len - 1UL,
                                        int addr,
                                        int (addr + len) - 1)
      dumpOneSection codeprn $"code object {n}" ptr)
  elif hasDumpableSections hdl then
    BinFileOps.getSections hdl.File
    |> Array.tryFind (fun sec -> sec.Name = name)
    |> function
      | Some sec -> dumpSection hdl opts codeprn tableprn sec
      | None -> ()
  else
    Terminator.futureFeature ()

let private dumpAllSections (hdl: BinHandle) opts codeprn tableprn =
  if hdl.File.Format = FileFormat.PythonBinary then
    dumpPythonCodeObjects hdl codeprn
  elif hasDumpableSections hdl then
    for sec in BinFileOps.getSections hdl.File do
      dumpSection hdl opts codeprn tableprn sec
  else
    Terminator.futureFeature ()

let private dumpRegularFile (hdl: BinHandle) (opts: BinDisasmOpts) =
  let codeprn = makeCodeDumper hdl opts
  let tableprn = makeTableDumper hdl opts
  let opts = { opts with ShowSymbols = true }
  match opts.InputSecName with
  | Some secName -> dumpOneSectionOfName hdl opts codeprn tableprn secName
  | None -> dumpAllSections hdl opts codeprn tableprn

let private dumpFile (opts: BinDisasmOpts) filePath =
  let opts = { opts with ShowAddress = true }
  let hdl = BinHandle.LoadFile(filePath, opts.ISA, opts.BaseAddress)
  initTableConfig hdl.ISA opts.ShowLowUIR
  printFileName hdl.File.Path
  if isRawBinary hdl then dumpRawBinary hdl opts else dumpRegularFile hdl opts

let private dumpFiles files opts =
  match List.partition IO.File.Exists files with
  | [], [] ->
    eprintsn $"File(s) must be given.{Environment.NewLine}"
    CmdOpts.printUsage ToolName UsageTail BinDisasmOpts.Spec
  | files, [] ->
    Log.EnableCaching()
    files |> List.iter (dumpFile opts)
    Log.DisableCaching()
  | _, errs ->
    eprintsn <| "File(s) " + errs.ToString() + " not found!"

let private validateHexStringLength (hdl: BinHandle) isThumb hexstr =
  let liftingUnit = hdl.NewLiftingUnit()
  (* The mode has to be applied before reading the alignment, or a two-byte
     Thumb instruction gets rejected for not being a multiple of four. *)
  liftingUnit.IsThumb <- isThumb
  let alignment = liftingUnit.InstructionAlignment
  if (Array.length hexstr) % alignment = 0 then
    ()
  else
    eprintsn $"The hex string length must be multiple of {alignment}"
    exit 1

/// <summary>
/// Loads a hex string as a flat image, and says where in it the code sits.
///
/// Python cannot be read flat. An argument there indexes a table the code
/// object carries, so the parser wants a `.pyc` around the bytes rather than
/// the bytes alone -- which is why a hex string used to be the one input this
/// architecture had no answer for. The smallest file that can hold the given
/// bytecode is built around it here, so `-i python -s <hexstring>` reads the
/// same way every other architecture's does; the code then starts wherever
/// that file put it rather than at zero.
/// </summary>
let private loadHexString (opts: BinDisasmOpts) baseAddr =
  let hex, isa = opts.InputHexStr, opts.ISA
  if isa.Arch = Architecture.Python then
    let version = enum<PythonVersion> isa.Flags
    let magic = Python.Builder.magicOf version
    let pyc = Python.Builder.build version magic (Python.Builder.codeOf hex)
    let hdl = BinHandle.LoadFileBytes(pyc, isa)
    let bf = hdl.File :?> PythonBinFile
    let addr =
      match bf.CodeObj with
      | Python.PyCode co -> fst co.Code
      | _ -> 0UL
    hdl, int addr
  else
    BinHandle.LoadRawImage(hex, isa, baseAddr, OS.UnknownOS), 0

let private dumpHexString (opts: BinDisasmOpts) =
  let baseAddr = defaultArg opts.BaseAddress 0UL
  let hdl, offset = loadHexString opts baseAddr
  initTableConfig hdl.ISA opts.ShowLowUIR
  validateHexStringLength hdl opts.ThumbMode opts.InputHexStr
  let dumper = makeCodeDumper hdl { opts with ShowColor = true }
  let len = opts.InputHexStr.Length
  let ptr =
    BinFilePointer.CreateFileBacked(
      uint64 offset + baseAddr,
      uint64 offset + baseAddr + uint64 len - 1UL,
      offset,
      offset + len - 1
    )
  dumper.IsThumb <- opts.ThumbMode
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
