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

namespace B2R2.Utilities

open B2R2
open System
open OptParse

/// A common set of command-line options used in analyzing binaries.
type CmdOpts () =
  /// Verbosity
  member val Verbose = false with get, set

  /// Just a wrapper function that instantiate an OptParse.Option object.
  static member New<'a> ( descr, ?callback, ?required, ?extra, ?help,
                                 ?short, ?long, ?dummy, ?descrColor ) =
    new OptParse.Option<'a> ( descr, ?callback=callback, ?required=required,
                                     ?extra=extra, ?help=help,
                                     ?short=short, ?long=long,
                                     ?dummy=dummy, ?descrColor=descrColor )

  /// "-v" or "--verbose" option turns on the verbose mode.
  static member OptVerbose () =
    let cb (opts: #CmdOpts) _ =
      opts.Verbose <- true; opts
    CmdOpts.New ( descr = "Verbose mode",
                  callback = cb, short = "-v", long = "--verbose" )

  /// "-h" or "--help" option.
  static member OptHelp () =
    CmdOpts.New ( descr = "Show this usage",
                  help = true, short = "-h", long = "--help" )

  static member private parseCmdOpts spec defaultOpts argv showLogo usageTail =
    let termFn () = exit 1
    let prog = Environment.GetCommandLineArgs().[0]
    let usageGetter () =
      showLogo ()
      let tail = if String.IsNullOrEmpty usageTail then "" else " " + usageTail
      String.Format ("[Usage]{0}{0}dotnet run -- %o{1}",
                     Environment.NewLine, tail)
    try
      optParse spec usageGetter prog argv defaultOpts
    with
    | SpecErr msg ->
      eprintfn "Invalid spec: %s" msg
      exit 1
    | RuntimeErr msg ->
      eprintfn "Invalid command line args given: %s" msg
      usagePrint spec prog usageGetter termFn
    | e ->
      eprintfn "Fatal error: %s" e.Message
      usagePrint spec prog usageGetter termFn

  static member private writeIntro () =
    Utils.writeB2R2 false
    Console.WriteLine (", the Next-Generation Reversing Platform")
    Console.WriteLine (Attribution.copyright + Environment.NewLine)

  /// Parse command line arguments, and run the mainFn
  static member ParseAndRun mainFn usageTail optSpec (opts: #CmdOpts) args =
    let rest, opts =
      CmdOpts.parseCmdOpts optSpec opts args CmdOpts.writeIntro usageTail
    if opts.Verbose then CmdOpts.writeIntro () else ()
    try mainFn rest opts; 0
    with e -> eprintfn "Error: %s" e.Message
              eprintfn "%s" (if opts.Verbose then e.StackTrace else ""); 1

// vim: set tw=80 sts=2 sw=2:
