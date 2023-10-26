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
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile
open B2R2.RearEnd
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
      match isa.Arch with
      | Arch.IntelX86 | Arch.IntelX64 -> 36
      | _ -> 16
    [ LeftAligned addrWidth; LeftAligned binaryWidth; LeftAligned 10 ]

let private isARM32 (hdl: BinHandle) =
  match hdl.File.ISA.Arch with
  | Arch.ARMv7
  | Arch.AARCH32 -> true
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
      BinCodeDisasmPrinter (hdl, cfg, showSymb, showColor) :> BinPrinter

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
  let ptr = hdl.File.ToBinFilePointer hdl.File.BaseAddress
  let prn = makeCodePrinter hdl cfg opts
  prn.Print ptr
  out.PrintLine ()

let printHexdump (opts: BinDumpOpts) sec (hdl: BinHandle) =
  let ptr = BinFilePointer.OfSection sec
  let bytes = hdl.ReadBytes (ptr=ptr, nBytes=int sec.Size)
  let chunkSz = if opts.ShowWide then 32 else 16
  HexDumper.dump chunkSz hdl.File.ISA.WordSize opts.ShowColor ptr.Addr bytes
  |> Array.iter out.PrintLine

let private hasNoContent (sec: Section) (file: IBinFile) =
  match file with
  | :? ELFBinFile as file ->
    match file.TryFindSection sec.Name with
    | Some section -> section.SecType = ELF.SectionType.SHT_NOBITS
    | None -> true
  | _ -> false

let dumpHex (opts: BinDumpOpts) (sec: Section) (hdl: BinHandle) =
  if hasNoContent sec hdl.File then
    out.PrintTwoCols "" "NOBITS section."
  else printHexdump opts sec hdl
  out.PrintLine ()

let private createBinHandleFromPath (opts: BinDumpOpts) filePath =
  BinHandle (filePath, opts.ISA, opts.BaseAddress, opts.ArchOperationMode)

let private isRawBinary (hdl: BinHandle) =
  match hdl.File.Format with
  | FileFormat.ELFBinary
  | FileFormat.MachBinary
  | FileFormat.PEBinary
  | FileFormat.WasmBinary -> false
  | _ -> true

let private printCodeOrTable (printer: BinPrinter) sec =
  printer.Print (BinFilePointer.OfSection sec)
  out.PrintLine ()

let private printWasmCode (printer: BinPrinter) (code: Wasm.Code) =
  let locals = code.Locals
  let localsSize = List.sumBy (fun (l: Wasm.LocalDecl) -> l.LocalDeclLen) locals
  let offset = code.Offset + code.LenFieldSize + localsSize + 1
  let maxOffset = code.Offset + code.LenFieldSize + int32 code.CodeSize - 1
  let ptr = BinFilePointer (uint64 offset, offset, maxOffset)
  printer.Print ptr
  out.PrintLine ()

let initHandleForTableOutput (hdl: BinHandle) =
  match hdl.File.ISA.Arch with
  (* For ARM PLTs, we just assume the ARM mode (if no symbol is given). *)
  | Arch.ARMv7
  | Arch.AARCH32 -> hdl.Parser.OperationMode <- ArchOperationMode.ARMMode
  | _ -> ()

let private dumpSections hdl (opts: BinDumpOpts) (sections: seq<Section>) cfg =
  let mymode = (hdl: BinHandle).Parser.OperationMode
  let codeprn = makeCodePrinter hdl cfg opts
  let tableprn = makeTablePrinter hdl cfg opts
  sections
  |> Seq.iter (fun s ->
    if s.Size > 0u then
      out.PrintSectionTitle (String.wrapParen s.Name)
      match s.Kind with
      | SectionKind.ExecutableSection ->
        hdl.Parser.OperationMode <- mymode
        match hdl.File with
        | :? WasmBinFile as file ->
          match file.WASM.CodeSection with
          | Some sec ->
            match sec.Contents with
            | Some conts -> Seq.iter (printWasmCode codeprn) conts.Elements
            | None -> printCodeOrTable codeprn s
          | None -> printCodeOrTable codeprn s
        | _ -> printCodeOrTable codeprn s
      | SectionKind.LinkageTableSection ->
        initHandleForTableOutput hdl
        printCodeOrTable tableprn s
      | _ ->
        if opts.OnlyDisasm then printCodeOrTable codeprn s
        else dumpHex opts s hdl
    else ())

let private dumpRegularFile (hdl: BinHandle) (opts: BinDumpOpts) cfg =
  opts.ShowSymbols <- true
  match opts.InputSecName with
  | Some secname ->
    dumpSections hdl opts (hdl.File.GetSections (secname)) cfg
  | None ->
    dumpSections hdl opts (hdl.File.GetSections ()) cfg

let dumpFile (opts: BinDumpOpts) filepath =
  opts.ShowAddress <- true
  let hdl = createBinHandleFromPath opts filepath
  let cfg = getTableConfig hdl.File.ISA opts.ShowLowUIR
  printFileName hdl.File.Path
  if isRawBinary hdl then dumpRawBinary hdl opts cfg
  else dumpRegularFile hdl opts cfg

let dumpFileMode files (opts: BinDumpOpts) =
  match List.partition System.IO.File.Exists files with
  | [], [] ->
    Printer.PrintErrorToConsole "File(s) must be given."
    CmdOpts.PrintUsage ToolName UsageTail Cmd.spec
  | files, [] -> files |> List.iter (dumpFile opts)
  | _, errs ->
    Printer.PrintErrorToConsole ("File(s) " + errs.ToString() + " not found!")

let private assertBinaryLength isa mode hexstr =
  let multiplier = getInstructionAlignment isa mode
  if (Array.length hexstr) % multiplier = 0 then ()
  else
    Printer.PrintErrorToConsole <|
      "The hex string length must be multiple of " + multiplier.ToString ()
    exit 1

let dumpHexStringMode (opts: BinDumpOpts) =
  let hdl = BinHandle (opts.InputHexStr, opts.ISA, opts.BaseAddress, false)
  let cfg = getTableConfig hdl.File.ISA opts.ShowLowUIR
  assertBinaryLength opts.ISA opts.ArchOperationMode opts.InputHexStr
  opts.ShowColor <- true
  let printer = makeCodePrinter hdl cfg opts
  let baseAddr = defaultArg opts.BaseAddress 0UL
  let ptr = BinFilePointer (baseAddr, 0, opts.InputHexStr.Length - 1)
  printer.Print ptr
  out.PrintLine ()

let private dump files (opts: BinDumpOpts) =
#if DEBUG
  let sw = System.Diagnostics.Stopwatch.StartNew ()
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
