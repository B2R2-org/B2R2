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

module internal B2R2.RearEnd.BinExplorer.BatchMode

open System.IO
open B2R2
open B2R2.FrontEnd
open B2R2.MiddleEnd
open B2R2.MiddleEnd.ControlFlowAnalysis
open B2R2.RearEnd.Utils
open B2R2.RearEnd.Visualization

let visualizeGraph inputFile outputFile =
  Visualizer.visualizeFromFile inputFile outputFile

let toFileArray path =
  if Directory.Exists path then Directory.GetFiles path
  elif File.Exists path then [| path |]
  else [||]

let batchRun opts paths fstParam restParams fn =
  let cmdStore = CLI.spec |> CmdStore
  let files = paths |> List.map toFileArray
  let numFiles = List.fold (fun cnt arr -> Array.length arr + cnt) 0 files
  files
  |> List.iteri (fun idx1 arr ->
    Array.iteri (fun idx2 file ->
      let idx = 1 + idx1 + idx2
      printfn "Running %s ... (%d/%d)" file idx numFiles
      fn cmdStore opts file fstParam restParams) arr)

let runCommand (cmdStore: CmdStore) opts file cmd args =
  let isa = ISA Architecture.Intel
  let hdl = BinHandle(file, isa, None)
  let exnInfo = ExceptionInfo hdl
  let funcId = Strategies.FunctionIdentification(hdl, exnInfo)
  let cfgRecovery = Strategies.CFGRecovery()
  let strategies = [| funcId :> ICFGBuildingStrategy<_, _>; cfgRecovery |]
  let brew = BinaryBrew(hdl, exnInfo, strategies)
  cmdStore.Handle(brew, cmd, args)
  |> Array.iter Terminal.Out.Print

let showBatchUsage () =
  Terminal.Out
  <== "dotnet run -- [file(s) ...] [opt(s) ...] --batch <cmd> [args ...]"
  <== ""
  <== "  Any regular BinExplorer commands will work in batch mode, but we"
  <== "  also provide a list of special commands as described below."
  <== ""
  <== "[Special Commands]"
  <== ""
  <== "* visualize: visualize the given CFG, and return assigned coords."
  <== ""
  <== "    visualize <input json> <output json>"
  <=/ ""
  exit 1

let main args paths opts =
  match args with
  | "visualize" :: infile :: outfile :: _ -> visualizeGraph infile outfile
  | cmd :: args -> batchRun opts paths cmd args runCommand
  | _ -> showBatchUsage ()
