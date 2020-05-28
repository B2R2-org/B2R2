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

module B2R2.Utilities.BinExplorer.Main

open B2R2
open B2R2.FrontEnd
open B2R2.BinCorpus
open B2R2.BinGraph
open B2R2.MiddleEnd
open B2R2.Visualization
open B2R2.Utilities

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
  /// BinHandler will automatically detect file format by default. When a fat
  /// binary is given, we need to choose which architecture to explorer with
  /// this option.
  member val ISA = isa with get, set

  /// Enable readline mode or not.
  member val EnableReadLine = true with get, set

  /// Enable no-return analysis.
  member val EnableNoReturn = true with get, set

  /// Enable branch recovery analysis.
  member val EnableBranchRecovery = true with get, set

  /// List of analyses to perform.
  member __.GetAnalyses () =
    [ if __.EnableNoReturn then yield NoReturnAnalysis () :> IAnalysis
      if __.EnableBranchRecovery then yield BranchRecovery () :> IAnalysis ]

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
      (BinExplorerOpts.ToThis opts).IP <- arg.[0]; opts
    CmdOpts.New ( descr = "Specify IP <address> (default: localhost)",
                  extra = 1, callback = cb, long = "--ip" )

  static member OptPort () =
    let cb (opts: #CmdOpts) (arg: string []) =
      (BinExplorerOpts.ToThis opts).Port <- int arg.[0]; opts
    CmdOpts.New ( descr = "Specify host port <number> (default: 8282)",
                  extra = 1, callback = cb, short = "-p", long = "--port" )

  static member OptLogFile () =
    let cb (opts: #CmdOpts) (arg: string []) =
      (BinExplorerOpts.ToThis opts).LogFile <- arg.[0]; opts
    CmdOpts.New ( descr = "Specify log file <name> (default: B2R2.log)",
                  callback = cb, short = "-l", long = "--log" )

  /// "-a" or "--isa" option for specifying ISA.
  static member OptISA () =
    let cb (opts: #CmdOpts) (arg: string []) =
      (BinExplorerOpts.ToThis opts).ISA <- ISA.OfString arg.[0]; opts
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
      (BinExplorerOpts.ToThis opts).JsonDumpDir <- arg.[0]; opts
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

    CmdOpts.New ( descr="\n[Extra]\n", dummy=true )

    BinExplorerOpts.OptReadLine ()
    BinExplorerOpts.OptJsonDumpDir ()
    CmdOpts.OptVerbose ()
    CmdOpts.OptHelp ()

    CmdOpts.New ( descr="\n[Batch Mode]\n", dummy=true )
    CmdOpts.New ( descr="Run in batch mode (w/o interative shell).",
                  long = "--batch" )
  ]

let buildGraph (opts: BinExplorerOpts) handle =
  BinEssence.Init handle <| opts.GetAnalyses ()

let startGUI (opts: BinExplorerOpts) arbiter =
  HTTPServer.startServer arbiter opts.IP opts.Port opts.Verbose
  |> Async.Start

/// Dump each CFG into JSON file. This feature is implemented to ease the
/// development and debugging process, and may be removed in the future.
let dumpJsonFiles jsonDir ess =
  try System.IO.Directory.Delete(jsonDir, true) with _ -> ()
  System.IO.Directory.CreateDirectory(jsonDir) |> ignore
  Apparatus.getInternalFunctions ess.Apparatus
  |> Seq.iter (fun { CalleeID = id; Addr = addr } ->
    let disasmJsonPath = Printf.sprintf "%s/%s.disasmCFG" jsonDir id
    let cfg, root = ess.SCFG.GetFunctionCFG (Option.get addr)
    let lens = DisasmLens.Init ess.Apparatus
    let disasmcfg, _ = lens.Filter cfg [root] ess.Apparatus
    CFGExport.toJson disasmcfg disasmJsonPath)

let initBinHdl isa (name: string) =
  BinHandler.Init (isa, ArchOperationMode.NoMode, true, 0UL, name)

let interactiveMain files (opts: BinExplorerOpts) =
  if List.length files = 0 then
    eprintfn "A file should be given as input.\n\n\
              Type --help or --batch to see more info."; exit 1
  else
    let file = List.head files
    let ess = initBinHdl opts.ISA file |> buildGraph opts
    if opts.JsonDumpDir <> "" then dumpJsonFiles opts.JsonDumpDir ess else ()
    let arbiter = Protocol.genArbiter ess opts.LogFile
    startGUI opts arbiter
    CLI.start opts.EnableReadLine arbiter

let showBatchUsage () =
  eprintfn "dotnet run -- [file(s) ...] --batch <cmd> [args ...]"
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

let batchRun opts paths cmd args =
  let cmds = CmdSpec.speclist |> CmdMap.build
  let files = paths |> List.map toFileArray
  let numFiles = List.fold (fun cnt arr -> Array.length arr + cnt) 0 files
  files
  |> List.iteri (fun idx1 arr ->
       Array.iteri (fun idx2 f ->
         let idx = 1 + idx1 + idx2
         printfn "Running %s ... (%d/%d)" f idx numFiles
         let ess = initBinHdl ISA.DefaultISA f |> buildGraph opts
         Cmd.handle cmds ess cmd args
         |> Array.iter System.Console.WriteLine) arr)

let batchMain opts paths args =
  match args with
  | "visualize" :: infile :: outfile :: _ -> visualizeGraph infile outfile; 0
  | cmd :: args -> batchRun opts paths cmd args; 0
  | _ -> showBatchUsage ()

let convertArgsToLists (paths, args) =
  (Array.toList paths), (Array.tail args |> Array.toList)

[<EntryPoint>]
let main args =
  let opts = BinExplorerOpts (ISA.DefaultISA)
  match Array.tryFindIndex (fun a -> a = "--batch") args with
  | Some idx -> Array.splitAt idx args |> convertArgsToLists ||> batchMain opts
  | None -> CmdOpts.ParseAndRun interactiveMain "<binary file>" spec opts args

// vim: set tw=80 sts=2 sw=2:
