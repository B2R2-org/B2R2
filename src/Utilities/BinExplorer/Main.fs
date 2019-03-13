(*
    B2R2 - the Next-Generation Reversing Platform

    Author: Sang Kil Cha <sangkilc@kaist.ac.kr>
                    DongYeop Oh <oh51dy@kaist.ac.kr>

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
open B2R2.BinFile
open B2R2.FrontEnd
open B2R2.Visualization
open B2R2.Utilities

type BinExplorerOpts () =
    inherit CmdOpts()

    /// Host port number.
    member val Port = 8282 with get, set

    /// Enable visualization.
    member val EnableVisual = false with get, set

    /// Logging output file.
    member val LogFile = "B2R2.log" with get, set

    member val JsonLoadFile = "" with get, set

    member val JsonDumpFile = "./output.cfg" with get, set

    /// Dump each CFG in JSON format?
    member val JsonDumpDir = "" with get, set

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

    static member OptVisualization () =
        let cb (opts: #CmdOpts) (_arg: string []) =
            (BinExplorerOpts.ToThis opts).EnableVisual <- true; opts
        CmdOpts.New ( descr = "Enable CFG Visualization mode",
                                    callback = cb, long = "--visual" )

    static member OptJsonLoadFile () =
        let cb (opts: #CmdOpts) (arg: string []) =
            (BinExplorerOpts.ToThis opts).JsonLoadFile <- arg.[0]; opts
        CmdOpts.New ( descr = "File name to load CFG json",
                                    extra = 1, callback = cb, long = "--loadjson" )

    static member OptJsonDumpFile () =
        let cb (opts: #CmdOpts) (arg: string []) =
            (BinExplorerOpts.ToThis opts).JsonDumpFile <- arg.[0]; opts
        CmdOpts.New (
            descr = "File name to dump CFG json (default is ./output.cfg)",
            extra = 1, callback = cb, long = "--dumpjson" )

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

        CmdOpts.OptInputFile ()
        CmdOpts.OptISA ()
        CmdOpts.OptBaseAddr ()

        CmdOpts.New ( descr="\n[Host Configuration]\n", dummy=true )

        BinExplorerOpts.OptPort ()

        CmdOpts.New ( descr="\n[Logging Configuration]\n", dummy=true )

        BinExplorerOpts.OptLogFile ()

        CmdOpts.New ( descr="\n[Visualization Configuration]\n", dummy=true )

        BinExplorerOpts.OptVisualization ()
        BinExplorerOpts.OptJsonLoadFile ()
        BinExplorerOpts.OptJsonDumpFile ()

        CmdOpts.New ( descr="\n[Extra]\n", dummy=true )

        BinExplorerOpts.OptReadLine ()
        BinExplorerOpts.OptJsonDumpDir ()
        CmdOpts.OptQuite ()
        CmdOpts.OptHelp ()
    ]

let visualizeGraph inputFile outputFile =
    Visualizer.visualizeFile inputFile outputFile

let buildGraph verbose handle =
    let ess = BinEssence.Init verbose handle
    ess

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

let initBinHdl name =
    let fmt, isa = FormatDetector.detect name
    BinHandler.Init (isa, ArchOperationMode.NoMode, fmt, 0UL, name)

let realMain (opts: BinExplorerOpts) =
    if Array.isEmpty opts.InputStr && String.length opts.InputFile = 0 &&
        not opts.EnableVisual then
        eprintfn "A string, a file, or a visual mode option should be given.\n\n\
                            See B2R2 --help for more info."; exit 1
    else ()
    if opts.EnableVisual then
        let inputJson = opts.JsonLoadFile
        let outputJson = opts.JsonDumpFile
        visualizeGraph inputJson outputJson
    else
        let ess = initBinHdl opts.InputFile |> buildGraph opts.Verbose
        if opts.JsonDumpDir <> "" then dumpJsonFiles opts.JsonDumpDir ess
        else ()
        let arbiter = Protocol.genArbiter ess opts.LogFile
        startGUI opts arbiter
        CLI.start opts.EnableReadLine arbiter

[<EntryPoint>]
let main args =
    let opts = BinExplorerOpts ()
    CmdOpts.ParseAndRun realMain spec opts args

// vim: set tw=80 sts=2 sw=2:
