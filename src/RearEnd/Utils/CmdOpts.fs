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

/// Provides utility functions for parsing command line options.
module B2R2.RearEnd.Utils.CmdOpts

open System
open B2R2
open B2R2.Logging
open B2R2.FsOptParse

/// Writes B2R2 logo to console. We can selectively append a new line at the
/// end.
let writeB2R2 printNewLine =
  ColoredString()
    .Add(DarkCyan, "B")
    .Add(DarkYellow, "2")
    .Add(DarkCyan, "R")
    .Add(DarkYellow, "2")
  |> Log.Out.Print
  if printNewLine then Log.Out.PrintLine()
  else ()

/// Writes introduction message to console.
let writeIntro () =
  writeB2R2 false
  Log.Out
  <== ", the Next-Generation Reversing Platform"
  <=/ Attribution.Copyright + Environment.NewLine

let private createUsage tool usageTail =
  let tail = if String.IsNullOrEmpty usageTail then "" else " " + usageTail
  String.Format("[Usage]{0}{0}b2r2 {1} %o{2}", Environment.NewLine, tool, tail)

let private createUsageFormatter tool usageTail =
  { new IUsageFormatter with
      member _.UsageForm with get() = createUsage tool usageTail
      member _.UsagePreCallback() = writeIntro () }

/// Prints out the usage message for the given tool.
let printUsage tool usageTail spec =
  let prog = Environment.GetCommandLineArgs()[0]
  let usageFormatter = createUsageFormatter tool usageTail
  OptParse.PrintUsage(spec, prog, usageFormatter)

let private parseCmdOpts spec defaultOpts argv tool usageTail =
  let prog = Environment.GetCommandLineArgs()[0]
  let usageFormatter = createUsageFormatter tool usageTail
  try
    OptParse.Parse(spec, usageFormatter, prog, argv, defaultOpts)
  with
  | SpecError msg ->
    Log.Out <=? $"Invalid spec: {msg}"
    exit 1
  | RuntimeError msg ->
    Log.Out <=? $"Invalid command line args given: {msg}"
    OptParse.PrintUsage(spec, prog, usageFormatter)
  | e ->
    Log.Out <=? $"Fatal error: {e.Message}"
    OptParse.PrintUsage(spec, prog, usageFormatter)

/// Parses command line arguments and runs the mainFn
let parseAndRun mainFn tool usageTail spec (opts: #IVerboseOption) args =
  let rest, opts = parseCmdOpts spec opts args tool usageTail
  if opts.IsVerbose then writeIntro () else ()
  try
    mainFn rest opts
    0
  with e ->
    Log.Out <=? $"{e.Message}"
    if opts.IsVerbose then Log.Out <=? e.StackTrace else ()
    1

/// Checks if the rest args contain an option string. If so, exit the program.
/// Otherwise, do nothing.
let rec sanitizeRestArgs args =
  match args with
  | arg :: rest ->
    if (arg: string).StartsWith('-') then
      Log.Out <=? sprintf "Invalid argument (%s) is used" arg
      exit 1
    else sanitizeRestArgs rest
  | [] -> ()
