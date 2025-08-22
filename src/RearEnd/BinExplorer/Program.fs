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

let startGUI (opts: BinExplorerOpts) arbiter =
  HTTPServer.startServer arbiter opts.IP opts.Port opts.Verbose
  |> Async.Start

/// Dump each CFG into JSON file. This feature is implemented to ease the
/// development and debugging process, and may be removed in the future.
let dumpJsonFiles jsonDir (brew: BinaryBrew<_, _>) =
  try Directory.Delete(jsonDir, true) with _ -> ()
  Directory.CreateDirectory(jsonDir) |> ignore
  brew.Functions.Sequence
  |> Seq.iter (fun func ->
    let id = func.ID
    let disasmJsonPath = Printf.sprintf "%s/%s.disasmCFG" jsonDir id
    if isNull func.CFG then ()
    else
      let file = brew.BinHandle.File
      let disasmBuilder = StringDisasmBuilder(true, file, file.ISA.WordSize)
      let disasmcfg = DisasmCFG(disasmBuilder, func.CFG)
      let s = Serializer.ToJson disasmcfg
      File.WriteAllText(disasmJsonPath, s))

let initBinHdl isa (name: string) =
  BinHandle(name, isa, None)

let startGUIAndCLI (opts: BinExplorerOpts) brew =
  if opts.JsonDumpDir <> "" then dumpJsonFiles opts.JsonDumpDir brew else ()
  let arbiter = Protocol.genArbiter brew opts.LogFile
  startGUI opts arbiter
  CLI.start opts.EnableReadLine arbiter

let interactiveMain files (opts: BinExplorerOpts) =
  if List.isEmpty files then
    eprintfn "A file should be given as input.\n\n\
              Type --help or --batch to see more info."; exit 1
  else
    let file = List.head files
    let isa = opts.ISA
    let hdl = initBinHdl isa file
    match isa.Arch with
    | Architecture.EVM ->
      let cfgRecovery = Strategies.EVMCFGRecovery()
      let brew = EVMBinaryBrew(hdl, [| cfgRecovery |])
      startGUIAndCLI opts brew
    | _ ->
      let exnInfo = ExceptionInfo hdl
      let funcId = Strategies.FunctionIdentification(hdl, exnInfo)
      let cfgRecovery = Strategies.CFGRecovery()
      let strategies = [| funcId :> ICFGBuildingStrategy<_, _>; cfgRecovery |]
      let brew = BinaryBrew(hdl, exnInfo, strategies)
      startGUIAndCLI opts brew

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
  if Directory.Exists path then Directory.GetFiles path
  elif File.Exists path then [| path |]
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
  let funcId = Strategies.FunctionIdentification(hdl, exnInfo)
  let cfgRecovery = Strategies.CFGRecovery()
  let strategies = [| funcId :> ICFGBuildingStrategy<_, _>; cfgRecovery |]
  let brew = BinaryBrew(hdl, exnInfo, strategies)
  Cmd.handle cmdMap brew cmd args
  |> Array.iter Terminal.Out.Print

let [<Literal>] private ToolName = "binexplore"

let batchMain opts paths args =
  match args with
  | "visualize" :: infile :: outfile :: _ -> visualizeGraph infile outfile
  | cmd :: args -> batchRun opts paths cmd args runCommand
  | _ -> showBatchUsage ()

let parseAndRunBatchMode opts spec (beforeOpts, afterOpts) =
  let main rest opts =
    batchMain opts rest (Array.tail afterOpts |> Array.toList)
  CmdOpts.parseAndRun main ToolName "" spec opts beforeOpts

[<EntryPoint>]
let main args =
  let isa = ISA Architecture.Intel (* default ISA *)
  let opts = BinExplorerOpts.Default isa
  let spec = BinExplorerOpts.Spec
  match Array.tryFindIndex (fun a -> a = "--batch") args with
  | Some idx ->
    Array.splitAt idx args |> parseAndRunBatchMode opts spec
  | None ->
    CmdOpts.parseAndRun interactiveMain ToolName "<binfile>" spec opts args
