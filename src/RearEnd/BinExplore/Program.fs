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

module B2R2.RearEnd.BinExplore.Program

open B2R2
open B2R2.FrontEnd
open B2R2.MiddleEnd
open B2R2.MiddleEnd.ControlFlowAnalysis
open B2R2.RearEnd.Utils

let [<Literal>] private ToolName = "explore"

let [<Literal>] private UsageTail = "<binary file>"

let private startGUIAndCLI (opts: BinExploreOpts) brew =
  let arbiter = Arbiter(brew, opts.LogFile)
  let cmdStore = CLI.spec |> CmdStore
  HTTPServer.start arbiter opts.IP opts.Port opts.Verbose cmdStore
  CLI.start arbiter cmdStore

let private startWithFile file (opts: BinExploreOpts) =
  let isa = opts.ISA
  let hdl = BinHandle(file, isa, None)
  match isa with
  | EVM ->
    let cfgRecovery = Strategies.EVMCFGRecovery()
    EVMBinaryBrew(hdl, [| cfgRecovery |])
    |> startGUIAndCLI opts
  | _ ->
    let exnInfo = ExceptionInfo hdl
    let funcId = Strategies.FunctionIdentification(hdl, exnInfo)
    let cfgRecovery = Strategies.CFGRecovery()
    let strategies = [| funcId :> ICFGBuildingStrategy<_, _>; cfgRecovery |]
    BinaryBrew(hdl, exnInfo, strategies)
    |> startGUIAndCLI opts

let private explore files opts =
  CmdOpts.sanitizeRestArgs files
  match files with
  | [] ->
    eprintsn "File should be given as input."
    CmdOpts.printUsage ToolName UsageTail BinExploreOpts.Spec
  | file :: _ ->
    startWithFile file opts

[<EntryPoint>]
let main args =
  let isa = ISA Architecture.Intel (* default ISA *)
  let opts = BinExploreOpts.Default isa
  CmdOpts.parseAndRun explore ToolName UsageTail BinExploreOpts.Spec opts args
