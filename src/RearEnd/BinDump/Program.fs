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

module B2R2.RearEnd.BinDump.Program

open B2R2
open B2R2.BinIR
open B2R2.FrontEnd.BinInterface
open B2R2.RearEnd
open B2R2.RearEnd.BinDump.Helper

let dumpSections (opts: BinDumpOpts) hdl =
  Utils.futureFeature ()

let dumpSection (secname: string) hdl =
  Utils.futureFeature ()

let printSelectively opts hdl = function
  | DisplayDumpSections -> dumpSections opts hdl
  | DisplayDumpSection s -> dumpSection s hdl

let printFileName filepath =
  [ Green, "["; Yellow, filepath; Green, "]" ] |> Printer.println
  Printer.println ()

let dumpFile (opts: BinDumpOpts) (filepath: string) =
  let hdl = BinHandle.Init (opts.ISA, opts.BaseAddress, filepath)
  let fi = hdl.FileInfo
  printFileName fi.FilePath
  if opts.DisplayItems.Count = 0 then printError "Option(s) must be given."
  else opts.DisplayItems |> Seq.iter (printSelectively opts hdl)

let dumpString (opts: BinDumpOpts) =
  Utils.futureFeature ()

let [<Literal>] private toolName = "bindump"
let [<Literal>] private usageTail = "<binary file(s)>"

let dump files (opts: BinDumpOpts) =
  if Array.isEmpty opts.InputStr then
    match files with
    | [] ->
      printError "File(s) must be given."
      CmdOpts.PrintUsage toolName usageTail Cmd.spec
    | files -> files |> List.iter (dumpFile opts)
  else
    dumpString opts

[<EntryPoint>]
let main args =
  let opts = BinDumpOpts ()
  CmdOpts.ParseAndRun dump toolName usageTail Cmd.spec opts args

// vim: set tw=80 sts=2 sw=2:
