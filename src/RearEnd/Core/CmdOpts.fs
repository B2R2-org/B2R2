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

namespace B2R2.RearEnd

open B2R2
open B2R2.FsOptParse
open System

module CS = ColoredSegment

/// A common set of command-line options used in analyzing binaries.
type CmdOpts () =
  /// Verbosity
  member val Verbose = false with get, set

  /// Just a wrapper function that instantiate an OptParse.Option object.
  static member New<'a> (descr, ?callback, ?required, ?extra, ?help,
                                ?short, ?long, ?dummy, ?descrColor) =
    Option<'a> (descr,
                ?callback=callback,
                ?required=required,
                ?extra=extra, ?help=help,
                ?short=short, ?long=long,
                ?dummy=dummy, ?descrColor=descrColor)

  /// "-v" or "--verbose" option turns on the verbose mode.
  static member OptVerbose () =
    let cb (opts: #CmdOpts) _ =
      opts.Verbose <- true; opts
    CmdOpts.New (descr = "Verbose mode",
                 callback = cb, short = "-v", long = "--verbose")

  /// "-h" or "--help" option.
  static member OptHelp () =
    CmdOpts.New (descr = "Show this usage",
                 help = true, short = "-h", long = "--help")

  /// Write B2R2 logo to console. We can selectively append a new line at the
  /// end.
  static member WriteB2R2 newLine =
    [ CS.dcyan "B"; CS.dyellow "2"; CS.dcyan "R"; CS.dyellow "2" ]
    |> Printer.print
    if newLine then Printer.println () else ()

  static member private WriteIntro () =
    CmdOpts.WriteB2R2 false
    Printer.println (", the Next-Generation Reversing Platform")
    Printer.println (Attribution.copyright + Environment.NewLine)

  static member private CreateUsageGetter tool usageTail =
    fun () ->
      CmdOpts.WriteIntro ()
      let tail = if String.IsNullOrEmpty usageTail then "" else " " + usageTail
      String.Format ("[Usage]{0}{0}dotnet b2r2 {1} %o{2}",
                     Environment.NewLine, tool, tail)

  static member private TermFunction () = exit 1

  static member private parseCmdOpts spec defaultOpts argv tool usageTail =
    let prog = Environment.GetCommandLineArgs().[0]
    let usageGetter = CmdOpts.CreateUsageGetter tool usageTail
    try
      optParse spec usageGetter prog argv defaultOpts
    with
    | SpecErr msg ->
      eprintfn "Invalid spec: %s" msg
      exit 1
    | RuntimeErr msg ->
      eprintfn "Invalid command line args given: %s" msg
      usagePrint spec prog usageGetter CmdOpts.TermFunction
    | e ->
      eprintfn "Fatal error: %s" e.Message
      usagePrint spec prog usageGetter CmdOpts.TermFunction

  static member PrintUsage tool usageTail spec =
    let prog = Environment.GetCommandLineArgs().[0]
    let usageGetter = CmdOpts.CreateUsageGetter tool usageTail
    usagePrint spec prog usageGetter CmdOpts.TermFunction

  /// Parse command line arguments, and run the mainFn
  static member ParseAndRun mainFn tool usageTail spec (opts: #CmdOpts) args =
    let rest, opts = CmdOpts.parseCmdOpts spec opts args tool usageTail
    if opts.Verbose then CmdOpts.WriteIntro () else ()
    try mainFn rest opts; 0
    with e -> eprintfn "Error: %s" e.Message
              eprintfn "%s" (if opts.Verbose then e.StackTrace else ""); 1

  /// Check if the rest args contain an option string. If so, exit the program.
  /// Otherwise, do nothing.
  static member SanitizeRestArgs args =
    let rec sanitize = function
      | (arg: string) :: rest ->
        if arg.StartsWith ('-') then
          Printer.printError <| sprintf "Invalid argument (%s) is used" arg
          exit 1
        else sanitize rest
      | [] -> ()
    sanitize args

// vim: set tw=80 sts=2 sw=2:
