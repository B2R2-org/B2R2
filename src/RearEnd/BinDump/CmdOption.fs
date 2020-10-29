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

namespace B2R2.RearEnd.BinDump

open B2R2
open B2R2.RearEnd
open System
open System.Collections.Generic

type DumpMethod =
  | Disassemble
  | LowUIRLift (* Default *)

type OptOption =
  | NoOpt
  | Opt
  | OptPar

type BinDumpOpts () =
  inherit CmdOpts()

  let items = HashSet<DisplayItem> ()

  /// Display items.
  member val DisplayItems = items with get

  /// ISA
  member val ISA = ISA.Init (Arch.IntelX86) Endian.Little with get, set

  /// Base address
  member val BaseAddress: Addr = 0UL with get, set

  /// Input string from command line.
  member val InputStr: byte [] = [||] with get, set

  /// ArchOperationMode
  member val ArchOperationMode = ArchOperationMode.NoMode with get, set

  /// Whether to show addresses or not
  member val ShowAddress = false with get, set

  /// Show symbols or not?
  member val ShowSymbols = false with get, set

  /// Disassemble or IR-translate?
  member val DumpMethod = LowUIRLift with get, set

  /// Perform basic block optimization or not?
  member val DoOptimization = NoOpt with get, set

  /// Discover binary file format or not?
  member val AutoDetect = true with get, set

  static member private ToThis (opts: CmdOpts) =
    match opts with
    | :? BinDumpOpts as opts -> opts
    | _ -> failwith "Invalid Opts."

  static member private AddOpt (opts: #CmdOpts) item =
    (BinDumpOpts.ToThis opts).DisplayItems.Add item |> ignore
    opts

  /// "-h" or "--help" option.
  static member OptHelp () =
    CmdOpts.New (descr = "Show this usage", help = true, long = "--help")

  /// "-i" or "--isa" option for specifying ISA.
  static member OptISA () =
    let cb opts (arg: string []) =
      (BinDumpOpts.ToThis opts).ISA <- ISA.OfString arg.[0]
      opts
    CmdOpts.New ( descr = "Specify <ISA> (e.g., x86) from command line",
                  extra = 1, callback = cb, short = "-i", long= "--isa" )

  /// "-r" or "--base-addr" option for specifying a base address.
  static member OptBaseAddr () =
    let cb opts (arg: string []) =
      (BinDumpOpts.ToThis opts).BaseAddress <- Convert.ToUInt64 (arg.[0], 16)
      (BinDumpOpts.ToThis opts).ShowAddress <- true
      opts
    CmdOpts.New ( descr = "Specify the base <address> in hex (default=0)",
                  extra = 1, callback = cb, short = "-r", long = "--base-addr" )

  /// "-s" or "--full-contents" option for displaying contents of all sections.
  static member OptDumpSections () =
    let cb opts _ =
      BinDumpOpts.AddOpt opts DisplayDumpSections
    CmdOpts.New (
      descr = "Display contents of all sections",
      extra = 1, callback = cb, short = "-s", long= "--full-contents" )

  /// "-j" or "--section" for displaying contents of a specific section.
  static member OptDumpSection () =
    let cb opts (arg: string []) =
      BinDumpOpts.AddOpt opts (DisplayDumpSection arg.[0])
    CmdOpts.New (
      descr = "Display contents of a specific section",
      extra = 1, callback = cb, short = "-j", long= "--section" )

  /// "-S" option for specifying an input string.
  static member OptInputString () =
    let cb opts (arg: string []) =
      (BinDumpOpts.ToThis opts).InputStr <- ByteArray.ofHexString arg.[0]
      opts
    CmdOpts.New ( descr = "Specify an input <hexstring> from command line",
                  extra = 1, callback = cb, short = "-S" )

  /// "-m" or "--mode" option for specifying ArchOperationMode.
  static member OptArchMode () =
    let cb opts (arg: string []) =
      (BinDumpOpts.ToThis opts).ArchOperationMode <-
        ArchOperationMode.ofString arg.[0]
      opts
    CmdOpts.New (
      descr = "Specify <operation mode> (e.g., thumb/arm) from cmdline",
      extra = 1, callback = cb, short = "-m", long= "--mode" )

  /// "--show-addr" option decides whether to show addresses in disassembly.
  static member OptShowAddr () =
    let cb opts _ =
      (BinDumpOpts.ToThis opts).ShowAddress <- true
      opts
    CmdOpts.New ( descr = "Show addresses in disassembly",
                  callback = cb, long = "--show-addr" )

  static member OptShowSymbols () =
    let cb opts _ =
      (BinDumpOpts.ToThis opts).ShowSymbols <- true
      opts
    CmdOpts.New ( descr = "Show symbols while disassembling binary",
                  callback = cb, long = "--show-symbols")

  static member OptDisasm () =
    let cb opts _ =
      (BinDumpOpts.ToThis opts).DumpMethod <- Disassemble
      opts
    CmdOpts.New ( descr = "Disassemble binary (linear sweep)",
                  callback = cb, long = "--disasm")

  static member OptTransIR () =
    let cb opts _ =
      (BinDumpOpts.ToThis opts).DumpMethod <- LowUIRLift
      opts
    CmdOpts.New ( descr = "Translate a binary into an IL (default mode)",
                  callback = cb, long = "--translate")

  static member OptTransOptimization () =
    let cb opts _ =
      (BinDumpOpts.ToThis opts).DoOptimization <- Opt
      opts
    CmdOpts.New ( descr = "Perform bblock optimization for IL",
                  callback = cb, long = "--optimize")

  static member OptTransParOptimization () =
    let cb opts _ =
      (BinDumpOpts.ToThis opts).DoOptimization <- OptPar
      opts
    CmdOpts.New ( descr = "Perform parallel bblock optimization for IL",
                  callback = cb, long = "--par-optimize")

  static member OptRawBinary () =
    let cb opts _ =
      (BinDumpOpts.ToThis opts).AutoDetect <- false
      opts
    CmdOpts.New ( descr = "Turn off file format detection",
                  callback = cb, long = "--raw-binary" )

[<RequireQualifiedAccess>]
module Cmd =
  let spec: BinDumpOpts FsOptParse.Option list =
    [ CmdOpts.New (descr = "[General options]", dummy = true)
      CmdOpts.New (descr = "", dummy = true)

      BinDumpOpts.OptHelp ()
      CmdOpts.OptVerbose ()
      BinDumpOpts.OptISA ()
      BinDumpOpts.OptBaseAddr ()

      BinDumpOpts.OptDumpSections ()
      BinDumpOpts.OptDumpSection ()

      CmdOpts.New (descr = "", dummy = true)
      CmdOpts.New (descr = "[Input Configuration]", dummy = true)
      CmdOpts.New (descr = "", dummy = true)

      BinDumpOpts.OptInputString ()
      BinDumpOpts.OptArchMode ()
      BinDumpOpts.OptRawBinary ()

      CmdOpts.New (descr = "", dummy = true)
      CmdOpts.New (descr = "[Output Configuration]", dummy = true)
      CmdOpts.New (descr = "", dummy = true)

      BinDumpOpts.OptDisasm ()
      BinDumpOpts.OptTransIR ()
      BinDumpOpts.OptShowAddr ()
      BinDumpOpts.OptShowSymbols ()

      CmdOpts.New (descr = "", dummy = true)
      CmdOpts.New (descr = "[Optional Configuration]", dummy = true)
      CmdOpts.New (descr = "", dummy = true)

      BinDumpOpts.OptTransOptimization ()
      BinDumpOpts.OptTransParOptimization()

      CmdOpts.New (descr = "", dummy = true)
      CmdOpts.New (descr = "[Extra]", dummy = true)
      CmdOpts.New (descr = "", dummy = true) ]

// vim: set tw=80 sts=2 sw=2:
