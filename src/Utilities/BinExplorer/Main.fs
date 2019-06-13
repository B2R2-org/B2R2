(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>

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
open B2R2.BinGraph
open B2R2.FrontEnd
open B2R2.Visualization
open B2R2.Utilities

type BinExplorerOpts (isa) =
  inherit CmdOpts()

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

  /// Enable readline mode or not. This option will be removed when .NET bug:
  /// https://github.com/dotnet/corefx/issues/32174 is fixed.
  member val EnableReadLine = false with get, set

  static member private ToThis (opts: CmdOpts) =
    match opts with
    | :? BinExplorerOpts as opts -> opts
    | _ -> failwith "Invalid Opts."

  static member OptPort () =
    let cb (opts: #CmdOpts) (arg: string []) =
      (BinExplorerOpts.ToThis opts).Port <- int arg.[0]; opts
    CmdOpts.New ( descr = "Specify host port <number>",
                  callback = cb, short = "-p", long = "--port" )

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
      (BinExplorerOpts.ToThis opts).EnableReadLine <- true; opts
    CmdOpts.New (
      descr = "Enable readline feature for BinExplorer",
      callback = cb, long = "--readline")

  static member OptJsonDumpDir () =
    let cb (opts: #CmdOpts) (arg : string []) =
      (BinExplorerOpts.ToThis opts).JsonDumpDir <- arg.[0]; opts
    CmdOpts.New (
      descr = "Directory name to dump CFG json (do not dump if empty)",
      extra = 1, callback = cb, short = "-j", long = "--jsondir")

let spec =
  [
    CmdOpts.New ( descr="[Input Configuration]\n", dummy=true )

    BinExplorerOpts.OptISA ()

    CmdOpts.New ( descr="\n[Host Configuration]\n", dummy=true )

    BinExplorerOpts.OptPort ()

    CmdOpts.New ( descr="\n[Logging Configuration]\n", dummy=true )

    BinExplorerOpts.OptLogFile ()

    CmdOpts.New ( descr="\n[Extra]\n", dummy=true )

    BinExplorerOpts.OptReadLine ()
    BinExplorerOpts.OptJsonDumpDir ()
    CmdOpts.OptVerbose ()
    CmdOpts.OptHelp ()
  ]

let buildGraph verbose handle =
  BinEssence.Init verbose handle

let startGUI (opts: BinExplorerOpts) arbiter =
  HTTPServer.startServer arbiter opts.Port |> Async.Start

/// Dump each CFG into JSON file. This feature is implemented to ease the
/// development and debugging process, and may be removed in the future.
let dumpJsonFiles jsonDir ess =
  try System.IO.Directory.Delete(jsonDir, true) with _ -> ()
  System.IO.Directory.CreateDirectory(jsonDir) |> ignore
  List.iter
    (fun (func: Function) ->
      let disasmJsonPath = Printf.sprintf "%s/%s.disasmCFG" jsonDir func.Name
      let irJsonPath = Printf.sprintf "%s/%s.irCFG" jsonDir func.Name
      let encoding = System.Text.Encoding.UTF8
      let hdl = ess.BinHandler
      let disasmJson =
        CFGUtils.disasmCFGToJson hdl func.DisasmCFG func.Entry
        |> encoding.GetBytes
      let irJson =
        CFGUtils.irCFGToJson hdl func.IRCFG func.Entry |> encoding.GetBytes
      System.IO.File.WriteAllBytes(disasmJsonPath, disasmJson)
      System.IO.File.WriteAllBytes(irJsonPath, irJson)
    ) <| List.ofSeq ess.Functions.Values

let initBinHdl isa (name: string) =
  BinHandler.Init (isa, ArchOperationMode.NoMode, true, 0UL, name)

let interactiveMain files (opts: BinExplorerOpts) =
  if List.length files = 0 then
    eprintfn "A file should be given as input.\n\n\
              Type --help or --batch to see more info."; exit 1
  else
    let file = List.head files
    let ess = initBinHdl ISA.DefaultISA file |> buildGraph opts.Verbose
    if opts.JsonDumpDir <> "" then dumpJsonFiles opts.JsonDumpDir ess else ()
    let arbiter = Protocol.genArbiter ess opts.LogFile
    startGUI opts arbiter
    CLI.start opts.EnableReadLine arbiter

let showBatchUsage () =
  eprintfn "--batch <cmd> [args ...]"
  eprintfn ""
  eprintfn "[Available Commands]"
  eprintfn ""
  eprintfn "* visualize: visualize the given CFG, and return assigned coords."
  eprintfn ""
  eprintfn "    visualize <input json> <output json>"
  eprintfn ""
  eprintfn "* null: run basic analyses on the binary and exit (for debugging)."
  eprintfn ""
  eprintfn "    null <files/dirs>"
  exit 1

let visualizeGraph inputFile outputFile =
  Visualizer.visualizeFile inputFile outputFile

let toFileArray path =
  if System.IO.Directory.Exists path then System.IO.Directory.GetFiles path
  elif System.IO.File.Exists path then [| path |]
  else [||]

let nullrun = function
  | [] -> showBatchUsage ()
  | paths ->
    let files = paths |> List.map toFileArray
    let numFiles = List.fold (fun cnt arr -> Array.length arr + cnt) 0 files
    files
    |> List.iteri (fun idx1 arr ->
         Array.iteri (fun idx2 f ->
           let idx = 1 + idx1 + idx2
           printfn "Analyzing %s ... (%d/%d)" f idx numFiles
           initBinHdl ISA.DefaultISA f |> buildGraph false |> ignore) arr)

let batchMain args =
  match Array.toList args with
  | "visualize" :: infile :: outfile :: _ -> visualizeGraph infile outfile; 0
  | "null" :: rest -> nullrun rest; 0
  | _ -> showBatchUsage ()

[<EntryPoint>]
let main args =
  let opts = BinExplorerOpts (ISA.DefaultISA)
  if Array.tryHead args = Some "--batch" then batchMain (Array.tail args)
  else CmdOpts.ParseAndRun interactiveMain "<binary file>" spec opts args

// vim: set tw=80 sts=2 sw=2:
