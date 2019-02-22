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

namespace B2R2.Utilities

open B2R2
open System
open OptParse

/// A common set of command-line options used in analyzing binaries.
[<AbstractClass>]
type CmdOpts (?isa) =
  /// Input file path.
  member val InputFile = "" with get, set

  /// Input string from command line.
  member val InputStr: byte [] = [||] with get, set

  /// ISA
  member val ISA = defaultArg isa ISA.DefaultISA with get, set

  /// ArchOperationMode
  member val ArchOperationMode = ArchOperationMode.NoMode with get, set

  /// Base address
  member val BaseAddress: Addr = 0UL with get, set

  /// Whether to show addresses or not
  member val ShowAddress = false with get, set

  /// Verbosity
  member val Verbose = false with get, set

  /// Just a wrapper function that instantiate an OptParse.Option object.
  static member New<'a> ( descr, ?callback, ?required, ?extra, ?help,
                                 ?short, ?long, ?dummy, ?descrColor ) =
    new OptParse.Option<'a> ( descr, ?callback=callback, ?required=required,
                                     ?extra=extra, ?help=help,
                                     ?short=short, ?long=long,
                                     ?dummy=dummy, ?descrColor=descrColor )

  /// "-i" option for specifying an input file.
  static member OptInputFile () =
    let cb (opts: #CmdOpts) (arg: string []) =
      opts.InputFile <- arg.[0]; opts
    CmdOpts.New ( descr = "Specify an input <file>",
                  extra = 1, callback = cb, short = "-i" )

  /// "-s" option for specifying an input string.
  static member OptInputString () =
    let cb (opts: #CmdOpts) (arg: string []) =
      opts.InputStr <- ByteArray.ofHexString arg.[0]; opts
    CmdOpts.New ( descr = "Specify an input <hexstring> from command line",
                  extra = 1, callback = cb, short = "-s" )

  /// "-a" or "--isa" option for specifying ISA.
  static member OptISA () =
    let cb (opts: #CmdOpts) (arg: string []) =
      opts.ISA <- ISA.OfString arg.[0]; opts
    CmdOpts.New ( descr = "Specify <ISA> (e.g., x86) from command line",
                  extra = 1, callback = cb, short = "-a", long= "--isa" )

  /// "-m" or "--mode" option for specifying ArchOperationMode.
  static member OptArchMode () =
    let cb (opts: #CmdOpts) (arg: string []) =
      opts.ArchOperationMode <- ArchOperationMode.ofString arg.[0]; opts
    CmdOpts.New (
      descr = "Specify <operation mode> (e.g., thumb/arm) from cmdline",
      extra = 1, callback = cb, short = "-m", long= "--mode" )

  /// "-r" or "--base-addr" option for specifying a base address.
  static member OptBaseAddr () =
    let cb (opts: #CmdOpts) (arg: string []) =
      opts.BaseAddress <- Convert.ToUInt64 (arg.[0], 16)
      opts.ShowAddress <- true
      opts
    CmdOpts.New ( descr = "Specify the base <address> in hex (default=0)",
                  extra = 1, callback = cb, short = "-r", long = "--base-addr" )

  /// "--show-addr" option decides whether to show addresses in disassembly.
  static member OptShowAddr () =
    let cb (opts: #CmdOpts) _ =
      opts.ShowAddress <- true; opts
    CmdOpts.New ( descr = "Show addresses in disassembly",
                  callback = cb, long = "--show-addr" )

  /// "-q" or "--quite" option turns on the quiet mode.
  static member OptQuite () =
    let cb (opts: #CmdOpts) _ =
      opts.Verbose <- true; opts
    CmdOpts.New ( descr = "Verbose mode",
                  callback = cb, short = "-v", long = "--verbose" )

  /// "-h" or "--help" option.
  static member OptHelp () =
    CmdOpts.New ( descr = "Show this usage",
                  help = true, short = "-h", long = "--help" )

  static member private parseCmdOpts spec defaultOpts argv showLogo =
    let termFn () = exit 1
    let prog = Environment.GetCommandLineArgs().[0]
    let usageGetter () =
      showLogo ()
      String.Format ("[Usage]{0}{0}%p %o", Environment.NewLine)
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
  static member ParseAndRun mainFn optSpec (opts: #CmdOpts) args =
    let _, opts = CmdOpts.parseCmdOpts optSpec opts args CmdOpts.writeIntro
    if opts.Verbose then CmdOpts.writeIntro () else ()
    try mainFn opts; 0
    with e -> eprintfn "Error: %s" e.Message
              eprintfn "%s" (if opts.Verbose then e.StackTrace else ""); 1

// vim: set tw=80 sts=2 sw=2:
