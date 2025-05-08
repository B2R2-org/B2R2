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

module B2R2.RearEnd.BinExplorer.Program

open System.IO
open B2R2
open B2R2.FrontEnd
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis
open B2R2.RearEnd.Utils
open B2R2.RearEnd.Visualization
open B2R2.RearEnd.BinExplorer.CmdUtils

type BinExplorerOpts (isa) =
  inherit CmdOpts()

  /// IP address to bind.
  member val IP = "localhost" with get, set

  /// Host port number.
  member val Port = 8282 with get, set

  /// Logging output file.
  member val LogFile = "B2R2.log" with get, set

  /// If this is not empty, we will dump each CFG (in JSON format) into the
  /// given directory.
  member val JsonDumpDir = "" with get, set

  /// Specify ISA. This is only meaningful for universal (fat) binaries because
  /// BinHandle will automatically detect file format by default. When a fat
  /// binary is given, we need to choose which architecture to explorer with
  /// this option.
  member val ISA = isa with get, set

  /// Enable readline mode or not.
  member val EnableReadLine = true with get, set

  /// Enable no-return analysis.
  member val EnableNoReturn = true with get, set

  /// Enable branch recovery analysis.
  member val EnableBranchRecovery = true with get, set

  /// Enable branch recovery analysis.
  member val EnableGapComp = false with get, set

  /// ABI file for EVM byte code.
  member val EVMAbiFile = "" with get, set

  /// Enable analysis for EVM.
  member val EnableEVMAnalysis = true with get, set

  static member private ToThis (opts: CmdOpts) =
    match opts with
    | :? BinExplorerOpts as opts -> opts
    | _ -> failwith "Invalid Opts."

  /// We can specify an IP to use to enable remote access, but we should make
  /// sure the two things:
  /// (1) Make sure we have a permission to bind to the IP address. On Windows,
  ///     we may have to run `netsh` command to enable this. For example:
  ///     netsh http add urlacl url=http://192.168.1.1:8282/ user=sangkilc
  /// (2) Make sure firewall does not block the connection.
  static member OptIP () =
    let cb (opts: #CmdOpts) (arg: string []) =
      (BinExplorerOpts.ToThis opts).IP <- arg[0]; opts
    CmdOpts.New ( descr = "Specify IP <address> (default: localhost)",
                  extra = 1, callback = cb, long = "--ip" )

  static member OptPort () =
    let cb (opts: #CmdOpts) (arg: string []) =
      (BinExplorerOpts.ToThis opts).Port <- int arg[0]; opts
    CmdOpts.New ( descr = "Specify host port <number> (default: 8282)",
                  extra = 1, callback = cb, short = "-p", long = "--port" )

  static member OptLogFile () =
    let cb (opts: #CmdOpts) (arg: string []) =
      (BinExplorerOpts.ToThis opts).LogFile <- arg[0]; opts
    CmdOpts.New ( descr = "Specify log file <name> (default: B2R2.log)",
                  callback = cb, short = "-l", long = "--log" )

  /// "-a" or "--isa" option for specifying ISA.
  static member OptISA () =
    let cb (opts: #CmdOpts) (arg: string []) =
      (BinExplorerOpts.ToThis opts).ISA <- ISA.OfString arg[0]; opts
    CmdOpts.New ( descr = "Specify <ISA> (e.g., x86) for fat binaries",
                  extra = 1, callback = cb, short = "-a", long= "--isa" )

  static member OptReadLine () =
    let cb (opts: #CmdOpts) (_arg : string []) =
      (BinExplorerOpts.ToThis opts).EnableReadLine <- false; opts
    CmdOpts.New (
      descr = "Disable readline feature for BinExplorer",
      callback = cb, long = "--no-readline")

  static member OptJsonDumpDir () =
    let cb (opts: #CmdOpts) (arg : string []) =
      (BinExplorerOpts.ToThis opts).JsonDumpDir <- arg[0]; opts
    CmdOpts.New (
      descr = "Directory name to dump CFG json (no dump if empty)",
      extra = 1, callback = cb, short = "-j", long = "--jsondir")

  static member OptDisableNoReturn () =
    let cb (opts: #CmdOpts) (_arg : string []) =
      (BinExplorerOpts.ToThis opts).EnableNoReturn <- false; opts
    CmdOpts.New (
      descr = "Disable no-return analysis.",
      callback = cb, long = "--disable-no-return")

  static member OptDisableBranchRecovery () =
    let cb (opts: #CmdOpts) (_arg : string []) =
      (BinExplorerOpts.ToThis opts).EnableBranchRecovery <- false; opts
    CmdOpts.New (
      descr = "Disable indirect branch recovery analysis.",
      callback = cb, long = "--disable-branch-recovery")

  static member OptDisableSpeculativeGapCompletion () =
    let cb (opts: #CmdOpts) (_arg : string []) =
      (BinExplorerOpts.ToThis opts).EnableGapComp <- false; opts
    CmdOpts.New (
      descr = "Disable speculative gap completion.",
      callback = cb, long = "--disable-gap-completion")

  static member OptEVMAbiFile () =
    let cb (opts: #CmdOpts) (arg : string []) =
      (BinExplorerOpts.ToThis opts).EVMAbiFile <- arg[0]; opts
    CmdOpts.New (
      descr = "ABI file path for EVM bytecode.",
      extra = 1, callback = cb, long = "--evmabi")

  static member OptDisableEVMAnalysis () =
    let cb (opts: #CmdOpts) (_arg : string []) =
      (BinExplorerOpts.ToThis opts).EnableEVMAnalysis <- false; opts
    CmdOpts.New (
      descr = "Disable EVM analyses (for code copy and trampoline).",
      callback = cb, long = "--disable-evm-analysis")

let spec =
  [ CmdOpts.New ( descr="[Input Configuration]\n", dummy=true )

    BinExplorerOpts.OptISA ()

    CmdOpts.New ( descr="\n[Host Configuration]\n", dummy=true )

    BinExplorerOpts.OptIP ()
    BinExplorerOpts.OptPort ()

    CmdOpts.New ( descr="\n[Logging Configuration]\n", dummy=true )

    BinExplorerOpts.OptLogFile ()

    CmdOpts.New ( descr="\n[Analyses]\n", dummy=true )

    BinExplorerOpts.OptDisableNoReturn ()
    BinExplorerOpts.OptDisableBranchRecovery ()
    BinExplorerOpts.OptDisableSpeculativeGapCompletion ()

    CmdOpts.New ( descr="\n[Extra]\n", dummy=true )

    BinExplorerOpts.OptReadLine ()
    BinExplorerOpts.OptJsonDumpDir ()
    BinExplorerOpts.OptEVMAbiFile ()
    BinExplorerOpts.OptDisableEVMAnalysis ()
    CmdOpts.OptVerbose ()
    CmdOpts.OptHelp ()

    CmdOpts.New ( descr="\n[Batch Mode]\n", dummy=true )
    CmdOpts.New ( descr="Run in batch mode (w/o interative shell).",
                  long = "--batch" )
  ]

let startGUI (opts: BinExplorerOpts) arbiter =
  HTTPServer.startServer arbiter opts.IP opts.Port opts.Verbose
  |> Async.Start

/// Dump each CFG into JSON file. This feature is implemented to ease the
/// development and debugging process, and may be removed in the future.
let dumpJsonFiles jsonDir (brew: BinaryBrew<_, _>) =
  try System.IO.Directory.Delete(jsonDir, true) with _ -> ()
  System.IO.Directory.CreateDirectory(jsonDir) |> ignore
  brew.Functions.Sequence
  |> Seq.iter (fun func ->
    let id = func.ID
    let disasmJsonPath = Printf.sprintf "%s/%s.disasmCFG" jsonDir id
    if isNull func.CFG then ()
    else
      let file = brew.BinHandle.File
      let disasmBuilder = StringDisasmBuilder (true, file, file.ISA.WordSize)
      let disasmcfg = DisasmCFG (disasmBuilder, func.CFG)
      let s = Serializer.ToJson disasmcfg
      File.WriteAllText (disasmJsonPath, s))

let initBinHdl isa (name: string) =
  BinHandle (name, isa, None)

let interactiveMain files (opts: BinExplorerOpts) =
  if List.isEmpty files then
    eprintfn "A file should be given as input.\n\n\
              Type --help or --batch to see more info."; exit 1
  else
    let file = List.head files
    let hdl = initBinHdl opts.ISA file
    let brew = BinaryBrew hdl
    if opts.JsonDumpDir <> "" then dumpJsonFiles opts.JsonDumpDir brew else ()
    let arbiter = Protocol.genArbiter brew opts.LogFile
    startGUI opts arbiter
    CLI.start opts.EnableReadLine arbiter

let showBatchUsage () =
  eprintfn "dotnet run -- [file(s) ...] [opt(s) ...] --batch <cmd> [args ...]"
  eprintfn ""
  eprintfn "  Any regular BinExplorer commands will work in batch mode, but we"
  eprintfn "  also provide a list of special commands as described below."
  eprintfn ""
  eprintfn "[Special Commands]"
  eprintfn ""
  eprintfn "* visualize: visualize the given CFG, and return assigned coords."
  eprintfn ""
  eprintfn "    visualize <input json> <output json>"
  eprintfn ""
  exit 1

let visualizeGraph inputFile outputFile =
  Visualizer.visualizeFromFile inputFile outputFile

let toFileArray path =
  if System.IO.Directory.Exists path then System.IO.Directory.GetFiles path
  elif System.IO.File.Exists path then [| path |]
  else [||]

let batchRun opts paths fstParam restParams fn =
  let cmdMap = CmdSpec.speclist |> CmdMap.build
  let files = paths |> List.map toFileArray
  let numFiles = List.fold (fun cnt arr -> Array.length arr + cnt) 0 files
  files
  |> List.iteri (fun idx1 arr ->
       Array.iteri (fun idx2 file ->
         let idx = 1 + idx1 + idx2
         printfn "Running %s ... (%d/%d)" file idx numFiles
         fn cmdMap opts file fstParam restParams) arr)

let runCommand cmdMap opts file cmd args =
  let isa = ISA Architecture.Intel
  let hdl = initBinHdl isa file
  let exnInfo = ExceptionInfo hdl
  let funcId = Strategies.FunctionIdentification (hdl, exnInfo)
  let cfgRecovery = Strategies.CFGRecovery ()
  let strategies = [| funcId :> ICFGBuildingStrategy<_, _>; cfgRecovery |]
  let brew = BinaryBrew (hdl, exnInfo, strategies)
  Cmd.handle cmdMap brew cmd args
  |> Array.iter out.Print

let [<Literal>] private ToolName = "binexplore"

let batchMain opts paths args =
  match args with
  | "visualize" :: infile :: outfile :: _ -> visualizeGraph infile outfile
  | cmd :: args -> batchRun opts paths cmd args runCommand
  | _ -> showBatchUsage ()

let parseAndRunBatchMode opts (beforeOpts, afterOpts) =
  CmdOpts.ParseAndRun (fun rest opts ->
    batchMain opts rest (Array.tail afterOpts |> Array.toList)
  ) ToolName "" spec opts beforeOpts

[<EntryPoint>]
let main args =
  let isa = ISA Architecture.Intel (* default ISA *)
  let opts = BinExplorerOpts isa
  match Array.tryFindIndex (fun a -> a = "--batch") args with
  | Some idx -> Array.splitAt idx args |> parseAndRunBatchMode opts
  | None ->
    CmdOpts.ParseAndRun interactiveMain ToolName "<binfile>" spec opts args

// vim: set tw=80 sts=2 sw=2:
