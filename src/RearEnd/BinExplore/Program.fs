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

let private loadAllFiles (arbiter: Arbiter<_, _>) files =
  files
  |> List.forall (fun file -> arbiter.AddBinary file |> Result.isOk)
  |> fun ok -> assert ok

let private startServerAndCLI files (opts: BinExploreOpts) loader =
  let arbiter = Arbiter(loader, opts.LogFile)
  let cmdStore = CLI.spec |> CmdStore
  loadAllFiles arbiter files
  HTTPServer.start arbiter opts.IP opts.Port opts.Verbose cmdStore
  CLI.start arbiter cmdStore

let private runWithBrewLoader files (opts: BinExploreOpts) =
  match opts.ISA with
  | EVM ->
    { new IBrewLoadable<_, _> with
        member _.LoadBrew file =
          let hdl = BinHandle(file, opts.ISA, None)
          let cfgRecovery = Strategies.EVMCFGRecovery()
          EVMBinaryBrew(hdl, [| cfgRecovery |]) }
    |> startServerAndCLI files opts
  | _ ->
    { new IBrewLoadable<_, _> with
        member _.LoadBrew file =
          let hdl = BinHandle(file, opts.ISA, None)
          let exnInfo = ExceptionInfo hdl
          let funcId = Strategies.FunctionIdentification(hdl, exnInfo)
          let cfgRecovery = Strategies.CFGRecovery()
          let strategies =
            [| funcId :> ICFGBuildingStrategy<_, _>; cfgRecovery |]
          BinaryBrew(hdl, exnInfo, strategies) }
    |> startServerAndCLI files opts

let private explore files opts =
  CmdOpts.sanitizeRestArgs files
  String.replicate System.Console.WindowHeight System.Environment.NewLine
  |> System.Console.Write
  runWithBrewLoader files opts

[<EntryPoint>]
let main args =
  let isa = ISA Architecture.Intel (* default ISA *)
  let opts = BinExploreOpts.Default isa
  CmdOpts.parseAndRun explore ToolName UsageTail BinExploreOpts.Spec opts args
