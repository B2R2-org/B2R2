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

module B2R2.Utilities.BinDump

open B2R2
open B2R2.BinIR
open B2R2.BinFile
open B2R2.FrontEnd
open System

type DumpMethod =
  | Disassemble
  | LowUIRLift (* Default *)

type OptOption =
  | NoOpt
  | Opt
  | OptPar

type BinDumpOpts (autoDetect, isa) =
  inherit CmdOpts()

  /// Input file path.
  member val InputFile = "" with get, set

  /// Input string from command line.
  member val InputStr: byte [] = [||] with get, set

  /// ISA
  member val ISA = isa with get, set

  /// ArchOperationMode
  member val ArchOperationMode = ArchOperationMode.NoMode with get, set

  /// Base address
  member val BaseAddress: Addr = 0UL with get, set

  /// Whether to show addresses or not
  member val ShowAddress = false with get, set

  /// Show symbols or not?
  member val ShowSymbols = false with get, set

  /// Discover binary file format or not?
  member val AutoDetect = autoDetect with get, set

  /// Disassemble or IR-translate?
  member val DumpMethod = LowUIRLift with get, set

  /// Perform basic block optimization or not?
  member val DoOptimization = NoOpt with get, set

  static member private ToThis (opts: CmdOpts) =
    match opts with
    | :? BinDumpOpts as opts -> opts
    | _ -> failwith "Invalid Opts."

  /// "-a" or "--isa" option for specifying ISA.
  static member OptISA () =
    let cb (opts: #CmdOpts) (arg: string []) =
      (BinDumpOpts.ToThis opts).ISA <- ISA.OfString arg.[0]; opts
    CmdOpts.New ( descr = "Specify <ISA> (e.g., x86) from command line",
                  extra = 1, callback = cb, short = "-a", long= "--isa" )

  /// "-i" option for specifying an input file.
  static member OptInputFile () =
    let cb (opts: #CmdOpts) (arg: string []) =
      (BinDumpOpts.ToThis opts).InputFile <- arg.[0]; opts
    CmdOpts.New ( descr = "Specify an input <file>",
                  extra = 1, callback = cb, short = "-i" )

  /// "-s" option for specifying an input string.
  static member OptInputString () =
    let cb (opts: #CmdOpts) (arg: string []) =
      (BinDumpOpts.ToThis opts).InputStr <- ByteArray.ofHexString arg.[0]; opts
    CmdOpts.New ( descr = "Specify an input <hexstring> from command line",
                  extra = 1, callback = cb, short = "-s" )

  /// "-m" or "--mode" option for specifying ArchOperationMode.
  static member OptArchMode () =
    let cb (opts: #CmdOpts) (arg: string []) =
      (BinDumpOpts.ToThis opts).ArchOperationMode <-
        ArchOperationMode.ofString arg.[0]
      opts
    CmdOpts.New (
      descr = "Specify <operation mode> (e.g., thumb/arm) from cmdline",
      extra = 1, callback = cb, short = "-m", long= "--mode" )

  /// "-r" or "--base-addr" option for specifying a base address.
  static member OptBaseAddr () =
    let cb (opts: #CmdOpts) (arg: string []) =
      (BinDumpOpts.ToThis opts).BaseAddress <- Convert.ToUInt64 (arg.[0], 16)
      (BinDumpOpts.ToThis opts).ShowAddress <- true
      opts
    CmdOpts.New ( descr = "Specify the base <address> in hex (default=0)",
                  extra = 1, callback = cb, short = "-r", long = "--base-addr" )

  /// "--show-addr" option decides whether to show addresses in disassembly.
  static member OptShowAddr () =
    let cb (opts: #CmdOpts) _ =
      (BinDumpOpts.ToThis opts).ShowAddress <- true; opts
    CmdOpts.New ( descr = "Show addresses in disassembly",
                  callback = cb, long = "--show-addr" )

  static member OptShowSymbols () =
    let cb (opts: #CmdOpts) _ =
      (BinDumpOpts.ToThis opts).ShowSymbols <- true; opts
    CmdOpts.New ( descr = "Show symbols while disassembling binary",
                  callback = cb, long = "--show-symbols")

  static member OptDisasm () =
    let cb (opts: #CmdOpts) _ =
      (BinDumpOpts.ToThis opts).DumpMethod <- Disassemble; opts
    CmdOpts.New ( descr = "Disassemble binary (linear sweep)",
                  callback = cb, long = "--disasm")

  static member OptTransIR () =
    let cb (opts: #CmdOpts) _ =
      (BinDumpOpts.ToThis opts).DumpMethod <- LowUIRLift; opts
    CmdOpts.New ( descr = "Translate a binary into an IL (default mode)",
                  callback = cb, long = "--translate")

  static member OptTransOptimization () =
    let cb (opts: #CmdOpts) _ =
      (BinDumpOpts.ToThis opts).DoOptimization <- Opt; opts
    CmdOpts.New ( descr = "Perform bblock optimization for IL",
                  callback = cb, long = "--optimize")

  static member OptTransParOptimization () =
    let cb (opts: #CmdOpts) _ =
      (BinDumpOpts.ToThis opts).DoOptimization <- OptPar; opts
    CmdOpts.New ( descr = "Perform parallel bblock optimization for IL",
                  callback = cb, long = "--par-optimize")

  static member OptRawBinary () =
    let cb (opts: BinDumpOpts) _ =
      opts.AutoDetect <- false
      opts
    CmdOpts.New ( descr = "Turn off file format detection",
                  callback = cb, long = "--raw-binary" )

let spec =
  [
    CmdOpts.New (descr = "[Input Configuration]\n", dummy = true)

    BinDumpOpts.OptInputFile ()
    BinDumpOpts.OptInputString ()
    BinDumpOpts.OptISA ()
    BinDumpOpts.OptArchMode ()
    BinDumpOpts.OptRawBinary ()

    CmdOpts.New (descr = "\n[Output Configuration]\n", dummy = true)

    BinDumpOpts.OptDisasm ()
    BinDumpOpts.OptTransIR ()
    BinDumpOpts.OptShowAddr ()
    BinDumpOpts.OptShowSymbols ()

    CmdOpts.New (descr = "\n[Optional Configuration]\n", dummy = true)

    BinDumpOpts.OptBaseAddr ()
    BinDumpOpts.OptTransOptimization ()
    BinDumpOpts.OptTransParOptimization()

    CmdOpts.New (descr = "\n[Extra]\n", dummy = true)

    CmdOpts.OptVerbose ()
    CmdOpts.OptHelp ()
  ]

let initWithFile (opts: BinDumpOpts) =
  BinHandler.Init (
    opts.ISA,
    opts.ArchOperationMode,
    opts.AutoDetect,
    opts.BaseAddress,
    opts.InputFile
  )

let initWithBytes (opts: BinDumpOpts) =
  BinHandler.Init (
    opts.ISA,
    opts.ArchOperationMode,
    false,
    opts.BaseAddress,
    opts.InputStr
  )

let isInvalidCmdLine (opts: BinDumpOpts) =
  Array.isEmpty opts.InputStr && String.IsNullOrEmpty opts.InputFile

let checkHeaderMismatch hdl =
  if hdl.FileInfo.FileFormat = FileFormat.RawBinary then ()
  else Utils.assertEqual hdl.ISA.WordSize hdl.FileInfo.WordSize
                         FileFormatMismatchException

let initHandle (opts: BinDumpOpts) =
  if opts.InputStr.Length = 0 then
    initWithFile opts |> Utils.tap checkHeaderMismatch
  else initWithBytes opts

let getNextAddr hdl invalidInsAddr =
  let invalidInsLen =
    match hdl.ISA.Arch with
    | Arch.IntelX86 | Arch.IntelX64 -> 1UL
    | _ -> 4UL
  invalidInsAddr + invalidInsLen

let printIllegal () =
  Console.WriteLine "(illegal)"

let inline printIfNotEmpty s = match s with "" -> () | _ -> Console.WriteLine s

let inline parseUntil hdl ctxt sAddr eAddr =
  let rec loop hdl ctxt pc acc =
    if pc < eAddr then
      let res = BinHandler.TryParseInstr hdl ctxt pc
      match res with
      | Ok ins ->
        let ctxt = ins.NextParsingContext
        loop hdl ctxt (pc + uint64 ins.Length) (res :: acc)
      | Error _ -> loop hdl ctxt (getNextAddr hdl pc) (res :: acc)
    else List.rev acc
  loop hdl ctxt sAddr []

let pickNext hdl eAddr untilFn bbFn sAddr = function
  | Error (res, nextAddr) when nextAddr = eAddr ->
    bbFn res; None
  | Ok (_, nextAddr, _) | Error (_, nextAddr) when nextAddr > eAddr ->
    untilFn sAddr |> ignore; None
  | Ok (res, nextAddr, ctxt) -> bbFn res; Some (nextAddr, ctxt)
  | Error (res, nextAddr) ->
    bbFn res
    printIllegal ()
    Some (getNextAddr hdl nextAddr, hdl.DefaultParsingContext)

let printDisasmUntil hdl showAddr showSymbs sAddr eAddr =
  let printFn = function
    | Ok ins ->
      BinHandler.DisasmInstr hdl showAddr showSymbs ins |> Console.WriteLine
    | Error _ -> printIllegal ()
  parseUntil hdl hdl.DefaultParsingContext sAddr eAddr |> List.iter printFn

let printDisasm result = printIfNotEmpty result

let printBlkDisasm showAddr showSymbs hdl sA eA =
  let untilFn sA = printDisasmUntil hdl showAddr showSymbs sA eA
  let digest = pickNext hdl eA untilFn printDisasm
  let rec loop sA hdl ctxt =
    if sA >= eA then ()
    else
      BinHandler.DisasmBBlock hdl ctxt showAddr showSymbs sA
      |> digest sA
      |> function
        | Some (n, ctxt) -> loop n hdl ctxt
        | None -> ()
  loop sA hdl hdl.DefaultParsingContext

let printLowUIRUntil hdl sAddr eAddr =
  let printFn = function
    | Ok ins ->
      BinHandler.LiftInstr hdl ins
      |> LowUIR.Pp.stmtsToString
      |> Console.WriteLine
    | Error _ -> printIllegal ()
  parseUntil hdl hdl.DefaultParsingContext sAddr eAddr |> List.iter printFn

let printLowUIR = LowUIR.Pp.stmtsToString >> printIfNotEmpty

let printBlkLowUIR opt hdl sAddr eAddr =
  let untilFn sAddr = printLowUIRUntil hdl sAddr eAddr
  let digest = pickNext hdl eAddr untilFn (opt >> printLowUIR)
  let rec loop sAddr hdl ctxt =
    if sAddr >= eAddr then ()
    else let r = BinHandler.LiftBBlock hdl ctxt sAddr |> digest sAddr
         match r with Some (n, ctxt) -> loop n hdl ctxt | None -> ()
  loop sAddr hdl hdl.DefaultParsingContext

let getSectionRanges handle =
  let folder acc (section: Section) =
    if section.Size > 0UL then section.ToAddrRange () :: acc else acc
  handle.FileInfo.GetExecutableSections ()
  |> Seq.fold folder []
  |> List.sortBy (fun r -> r.Min)

let getActor action showAddr showSymbs hdl opt =
  match action, opt with
  | Disassemble, _     -> printBlkDisasm showAddr showSymbs hdl
  | LowUIRLift, NoOpt  -> printBlkLowUIR (fun x -> x) hdl
  | LowUIRLift, Opt    -> printBlkLowUIR (BinHandler.Optimize) hdl
  | LowUIRLift, OptPar -> Utils.futureFeature ()

let cmdErrExit () =
  eprintfn "Either a string or a file should be given.\n\n\
            See bindump --help for more info."
  exit 1

let dump _ (opts: BinDumpOpts) =
  if isInvalidCmdLine opts then cmdErrExit () else ()
  let handle = initHandle opts
  let secRanges = getSectionRanges handle
  let action = opts.DumpMethod
  let showAddr = opts.ShowAddress
  let showSymbs = opts.ShowSymbols
  let actor = opts.DoOptimization |> getActor action showAddr showSymbs handle
  if secRanges.IsEmpty then ()
  else
    secRanges
    |> List.iter (fun sR -> actor (AddrRange.GetMin sR) (AddrRange.GetMax sR))

[<EntryPoint>]
let main args =
  let opts = BinDumpOpts (true, ISA.Init (Arch.IntelX86) Endian.Little)
  CmdOpts.ParseAndRun dump "" spec opts args

// vim: set tw=80 sts=2 sw=2:
