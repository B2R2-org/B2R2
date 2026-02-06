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

module internal B2R2.RearEnd.BinExplorer.InteractiveMode

open System.IO
open B2R2
open B2R2.Logging
open B2R2.FrontEnd
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis

/// Dumps each CFG into JSON file. This feature is implemented to ease the
/// development and debugging process, and may be removed in the future.
let dumpJsonFiles jsonDir (brew: BinaryBrew<_, _>) =
  try Directory.Delete(jsonDir, true) with _ -> ()
  Directory.CreateDirectory(jsonDir) |> ignore
  brew.Functions.Sequence
  |> Seq.iter (fun func ->
    let id = func.ID
    let disasmJsonPath = Printf.sprintf "%s/%s.disasmCFG" jsonDir id
    let file = brew.BinHandle.File
    let disasmBuilder = StringDisasmBuilder(true, file, file.ISA.WordSize)
    let disasmcfg = DisasmCFG(disasmBuilder, func.CFG)
    let s = BinGraph.Serializer.ToJson disasmcfg
    File.WriteAllText(disasmJsonPath, s))

let startGUI (opts: BinExplorerOpts) arbiter =
  HTTPServer.startServer arbiter opts.IP opts.Port opts.Verbose
  |> Async.Start

let startGUIAndCLI (opts: BinExplorerOpts) brew =
  if opts.JsonDumpDir <> "" then dumpJsonFiles opts.JsonDumpDir brew else ()
  let arbiter = Arbiter(brew, opts.LogFile)
  startGUI opts arbiter
  CLI.start opts.EnableReadLine arbiter

let main files (opts: BinExplorerOpts) =
  if List.isEmpty files then
    Log.Out <=? "A file should be given as input."
    Log.Out <=/ "Type --help or --batch to see more info."
    exit 1
  else
    let file = List.head files
    let isa = opts.ISA
    let hdl = BinHandle(file, isa, None)
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