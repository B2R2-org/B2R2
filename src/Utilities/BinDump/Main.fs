(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>
          DongYeop Oh <oh51dy@kaist.ac.kr>
          Seung Il Jung <sijung@kaist.ac.kr>
          Minkyu Jung <hestati@kaist.ac.kr>

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
  inherit CmdOpts(isa)
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

    CmdOpts.OptInputFile ()
    CmdOpts.OptInputString ()
    CmdOpts.OptISA ()
    CmdOpts.OptArchMode ()
    BinDumpOpts.OptRawBinary ()

    CmdOpts.New (descr = "\n[Output Configuration]\n", dummy = true)

    BinDumpOpts.OptDisasm ()
    BinDumpOpts.OptTransIR ()
    CmdOpts.OptShowAddr ()

    CmdOpts.New (descr = "\n[Optional Configuration]\n", dummy = true)

    CmdOpts.OptBaseAddr ()
    BinDumpOpts.OptTransOptimization ()
    BinDumpOpts.OptTransParOptimization()

    CmdOpts.New (descr = "\n[Extra]\n", dummy = true)

    CmdOpts.OptQuite ()
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

let inline parseUntil hdl sAddr eAddr =
  let rec loop pc acc =
    if pc < eAddr then
      let r = BinHandler.TryParseInstr hdl pc
      match r with
      | Some ins -> loop (pc + uint64 ins.Length) (r :: acc)
      | None -> loop (getNextAddr hdl pc) (r :: acc)
    else List.rev acc
  loop sAddr []

let pickNext hdl eAddr untilFn bbFn sAddr = function
  | Ok (_, nextAddr) | Error (_, nextAddr) when nextAddr > eAddr ->
    untilFn sAddr |> ignore; None
  | Ok (res, nextAddr) -> bbFn res; Some nextAddr
  | Error (res, nextAddr) ->
    bbFn res; printIllegal (); getNextAddr hdl nextAddr |> Some

let printDisasmUntil hdl showAddr sAddr eAddr =
  let printFn = function
    | Some ins -> BinHandler.DisasmInstr hdl showAddr false ins
                  |> Console.WriteLine
    | None -> printIllegal ()
  parseUntil hdl sAddr eAddr |> List.iter printFn

let printDisasm result = printIfNotEmpty result

let printBlkDisasm showAddr hdl sA eA =
  let untilFn sA = printDisasmUntil hdl showAddr sA eA
  let digest = pickNext hdl eA untilFn printDisasm
  let rec loop sA =
    if sA >= eA then ()
    else match BinHandler.DisasmBBlock hdl showAddr false sA |> digest sA with
         | Some n -> loop n
         | None -> ()
  loop sA

let printLowUIRUntil hdl sAddr eAddr =
  let printFn = function
    | Some ins -> BinHandler.LiftInstr hdl ins
                  |> LowUIR.Pp.stmtsToString
                  |> Console.WriteLine
    | None -> printIllegal ()
  parseUntil hdl sAddr eAddr |> List.iter printFn

let printLowUIR = LowUIR.Pp.stmtsToString >> printIfNotEmpty

let printBlkLowUIR opt hdl sAddr eAddr =
  let untilFn sAddr = printLowUIRUntil hdl sAddr eAddr
  let digest = pickNext hdl eAddr untilFn (opt >> printLowUIR)
  let rec loop sAddr =
    if sAddr >= eAddr then ()
    else let r = BinHandler.LiftBBlock hdl sAddr |> digest sAddr
         match r with Some n -> loop n | None -> ()
  loop sAddr

let parPrinter = function
  | Ok r -> printIfNotEmpty r
  | Error r -> printIfNotEmpty r; printIllegal ()


let [<Literal>] parMaxThres = 64

let parOptAndPrint hdl =
  let lift = BinHandler.LiftInstr hdl
  let asyncBuilder x =
    async {
      return match x with
             | Ok (r) -> List.map lift r
                         |> Array.concat
                         |> BinHandler.Optimize
                         |> LowUIR.Pp.stmtsToString
                         |> Ok
             | Error (r) -> List.map lift r
                            |> Array.concat
                            |> BinHandler.Optimize
                            |> LowUIR.Pp.stmtsToString
                            |> Error }
  fun results ->
    List.map asyncBuilder results
    |> Async.Parallel
    |> Async.RunSynchronously
    |> Seq.iter parPrinter

let parPrintOptBlkLowUIR hdl sAddr eAddr =
  let optPrinter = parOptAndPrint hdl
  let rec loop sAddr acc len =
    if len >= parMaxThres then optPrinter (List.rev acc); loop sAddr [] 0
    elif sAddr >= eAddr then optPrinter (List.rev acc)
    else let (r, nAddr) = BinHandler.ParseBBlockWithAddr (hdl, sAddr)
         match r with
         | Ok _ when nAddr > eAddr ->
           optPrinter (List.rev acc)
           printLowUIRUntil hdl sAddr eAddr
         | Error _ when getNextAddr hdl nAddr > eAddr ->
           optPrinter (List.rev acc)
           printLowUIRUntil hdl sAddr eAddr
         | Ok (_) -> loop nAddr (r :: acc) (len + 1)
         | Error (_) -> loop (getNextAddr hdl nAddr) (r :: acc) (len + 1)
  loop sAddr [] 0

let getSectionRanges handle =
  let folder acc (section: Section) =
    if section.Size > 0UL then section.ToAddrRange () :: acc else acc
  handle.FileInfo.GetExecutableSections ()
  |> Seq.fold folder []
  |> List.sortBy (fun r -> r.Min)

let getActor action showAddr hdl opt =
  match action, opt with
  | Disassemble, _     -> printBlkDisasm showAddr hdl
  | LowUIRLift, NoOpt  -> printBlkLowUIR (fun x -> x) hdl
  | LowUIRLift, Opt    -> printBlkLowUIR (BinHandler.Optimize) hdl
  | LowUIRLift, OptPar -> parPrintOptBlkLowUIR hdl

let cmdErrExit () =
  eprintfn "Either a string or a file should be given.\n\n\
            See bindump --help for more info."
  exit 1

let dump (opts: BinDumpOpts) =
  if isInvalidCmdLine opts then cmdErrExit () else ()
  let handle = initHandle opts
  let secRanges = getSectionRanges handle
  let action = opts.DumpMethod
  let showAddr = opts.ShowAddress
  let actor = opts.DoOptimization |> getActor action showAddr handle
  if secRanges.IsEmpty then ()
  else List.iter (fun sR -> actor (AddrRange.GetMin sR) (AddrRange.GetMax sR))
        secRanges

[<EntryPoint>]
let main args =
  let opts = BinDumpOpts (true, ISA.Init (Arch.IntelX86) Endian.Little)
  CmdOpts.ParseAndRun dump spec opts args

// vim: set tw=80 sts=2 sw=2:
