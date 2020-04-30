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

module B2R2.Utilities.Assembler

open B2R2
open B2R2.Assembler
open System

type AssemblerOpts (isa) =
  inherit CmdOpts()

  /// Input file path.
  member val InputFile = "" with get, set

  /// Input string from command line.
  member val InputStr: string = "" with get, set

  /// ISA
  member val ISA = isa with get, set

  /// Base address
  member val BaseAddress: Addr = 0UL with get, set

  static member private ToThis (opts: CmdOpts) =
    match opts with
    | :? AssemblerOpts as opts -> opts
    | _ -> failwith "Invalid Opts."

  /// "-a" or "--isa" option for specifying ISA.
  static member OptISA () =
    let cb (opts: #CmdOpts) (arg: string []) =
      (AssemblerOpts.ToThis opts).ISA <- ISA.OfString arg.[0]; opts
    CmdOpts.New ( descr = "Specify <ISA> (e.g., x86) from command line",
                  extra = 1, callback = cb, short = "-a", long= "--isa" )

  /// "-i" option for specifying an input file.
  static member OptInputFile () =
    let cb (opts: #CmdOpts) (arg: string []) =
      (AssemblerOpts.ToThis opts).InputFile <- arg.[0]; opts
    CmdOpts.New ( descr = "Specify an input <file>",
                  extra = 1, callback = cb, short = "-i" )

  /// "-s" option for specifying an input string.
  static member OptInputString () =
    let cb (opts: #CmdOpts) (arg: string []) =
      (AssemblerOpts.ToThis opts).InputStr <- arg.[0]; opts
    CmdOpts.New ( descr = "Specify an input <string> from command line",
                  extra = 1, callback = cb, short = "-s" )

  /// "-r" or "--base-addr" option for specifying a base address.
  static member OptBaseAddr () =
    let cb (opts: #CmdOpts) (arg: string []) =
      (AssemblerOpts.ToThis opts).BaseAddress <- Convert.ToUInt64 (arg.[0], 16)
      opts
    CmdOpts.New ( descr = "Specify the base <address> in hex (default=0)",
                  extra = 1, callback = cb, short = "-r", long = "--base-addr" )

let spec =
  [ CmdOpts.New (descr = "[Input Configuration]\n", dummy = true)

    AssemblerOpts.OptInputFile ()
    AssemblerOpts.OptInputString ()
    AssemblerOpts.OptISA ()

    CmdOpts.New (descr = "\n[Optional Configuration]\n", dummy = true)

    AssemblerOpts.OptBaseAddr ()

    CmdOpts.New (descr = "\n[Extra]\n", dummy = true)

    CmdOpts.OptVerbose ()
    CmdOpts.OptHelp () ]

let isInvalidCmdLine (opts: AssemblerOpts) =
  String.IsNullOrEmpty opts.InputStr && String.IsNullOrEmpty opts.InputFile

let inline printIfNotEmpty s = match s with "" -> () | _ -> Console.WriteLine s

let cmdErrExit () =
  eprintfn "Either a string or a file should be given.\n\n\
            See assembler --help for more info."
  exit 1

let initAsmString (opts: AssemblerOpts) =
  if opts.InputStr.Length = 0 then IO.File.ReadAllText opts.InputFile
  else opts.InputStr

let asmMain _ (opts: AssemblerOpts) =
  if isInvalidCmdLine opts then cmdErrExit () else ()
  let assembler = AsmInterface (opts.ISA, opts.BaseAddress)
  initAsmString opts
  |> assembler.Run
  |> List.fold (fun addr bs ->
    printf "%08x: " addr; bs |> Array.iter (printf "%02x"); printfn ""
    addr + uint64 (Array.length bs)) opts.BaseAddress
  |> ignore

[<EntryPoint>]
let main args =
  let opts = AssemblerOpts (ISA.Init (Arch.IntelX86) Endian.Little)
  CmdOpts.ParseAndRun asmMain "" spec opts args

// vim: set tw=80 sts=2 sw=2:
