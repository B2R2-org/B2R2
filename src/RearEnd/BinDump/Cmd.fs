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
open B2R2.FrontEnd.BinLifter
open B2R2.RearEnd
open System

type OptOption =
  | NoOptimize
  | Optimize

type BinDumpOpts () =
  inherit CmdOpts ()
  /// ISA
  member val ISA = ISA.DefaultISA with get, set

  /// Base address
  member val BaseAddress: Addr option = None with get, set

  /// Input section name from command line.
  member val InputSecName: string option = None with get, set

  /// Input hexstring from command line.
  member val InputHexStr: byte [] = [||] with get, set

  /// ArchOperationMode
  member val ArchOperationMode = ArchOperationMode.NoMode with get, set

  /// Whether to show addresses or not
  member val ShowAddress = false with get, set

  /// Show symbols or not?
  member val ShowSymbols = false with get, set

  /// Show LowUIR or not?
  member val ShowLowUIR = false with get, set

  /// Show hexdump widely or not, 32 bytes (default 16 bytes)
  member val ShowWide = false with get, set

  /// Show hexdump colored or not, just for files not hexstring
  member val ShowColor = false with get, set

  /// Display only disassembly.
  member val OnlyDisasm = false with get, set

  /// Perform basic block optimization or not?
  member val DoOptimization = NoOptimize with get, set

  /// Discover binary file format or not?
  member val AutoDetect = true with get, set

  static member private ToThis (opts: CmdOpts) =
    match opts with
    | :? BinDumpOpts as opts -> opts
    | _ -> failwith "Invalid Opts."

  /// "-h" or "--help" option.
  static member OptHelp () =
    CmdOpts.New (descr = "Show this usage", help = true, long = "--help")

  /// "-i" or "--isa" option for specifying ISA.
  static member OptISA () =
    let cb opts (arg: string []) =
      (BinDumpOpts.ToThis opts).ISA <- ISA.OfString arg[0]
      opts
    CmdOpts.New (descr = "Specify <ISA> (e.g., x86) from command line",
                 extra = 1, callback = cb, short = "-i", long = "--isa")

  /// "-r" or "--base-addr" option for specifying a base address.
  static member OptBaseAddr () =
    let cb opts (arg: string []) =
      (BinDumpOpts.ToThis opts).BaseAddress <-
        Some (Convert.ToUInt64 (arg[0], 16))
      (BinDumpOpts.ToThis opts).ShowAddress <- true
      opts
    CmdOpts.New (descr = "Specify the base <address> in hex (default=0)",
                 extra = 1, callback = cb, short = "-r", long = "--base-addr")

  /// "--only-disasm" option for forcefully showing disassembly for all
  /// sections.
  static member OptOnlyDisasm () =
    let cb opts (arg: string []) =
      (BinDumpOpts.ToThis opts).OnlyDisasm <- true
      opts
    CmdOpts.New (
      descr = "Always display disassembly for all sections.",
      callback = cb, long = "--only-disasm")

  /// "--att" for using AT&T syntax.
  static member OptATTSyntax () =
    let cb opts _ =
      Intel.Disasm.setDisassemblyFlavor ATTSyntax
      opts
    CmdOpts.New (descr = "Use AT&T syntax for disassembling Intel instructions",
                 callback = cb, long = "--att")

  /// "-S" or "--section" for displaying contents of a specific section.
  static member OptDumpSection () =
    let cb opts (arg: string []) =
      (BinDumpOpts.ToThis opts).InputSecName <- Some arg[0]
      opts
    CmdOpts.New (
      descr = "Display the contents of a specific section",
      extra = 1, callback = cb, short = "-S", long = "--section")

  /// "-s" option for specifying an input hexstring.
  static member OptInputHexString () =
    let cb opts (arg: string []) =
      (BinDumpOpts.ToThis opts).InputHexStr <- ByteArray.ofHexString arg[0]
      opts
    CmdOpts.New (descr = "Specify an input <hexstring> from command line",
                 extra = 1, callback = cb, short = "-s")

  /// "-m" or "--mode" option for specifying ArchOperationMode.
  static member OptArchMode () =
    let cb opts (arg: string []) =
      (BinDumpOpts.ToThis opts).ArchOperationMode <-
        ArchOperationMode.ofString arg[0]
      opts
    CmdOpts.New (
      descr = "Specify <operation mode> (e.g., thumb/arm) from cmdline",
      extra = 1, callback = cb, short = "-m", long = "--mode")

  /// "--show-addr" option decides whether to show addresses of hexstring.
  static member OptShowAddr () =
    let cb opts _ =
      (BinDumpOpts.ToThis opts).ShowAddress <- true
      opts
    CmdOpts.New (descr = "Show addresses of hexstring",
                 callback = cb, long = "--show-addr")

  /// "--show-symbols" option decides whether to show symbols in disassembly.
  static member OptShowSymbols () =
    let cb opts _ =
      (BinDumpOpts.ToThis opts).ShowSymbols <- true
      opts
    CmdOpts.New (descr = "Show symbols while disassembling binary",
                 callback = cb, long = "--show-symbols")

  /// "--show-wide" option decides whether to show hexdump with 32 bytes.
  static member OptShowWide () =
    let cb opts _ =
      (BinDumpOpts.ToThis opts).ShowWide <- true
      opts
    CmdOpts.New (descr = "Show hexdump with 32 bytes long",
                 callback = cb, long = "--show-wide")

  /// "--show-color" option decides whether to show colored hexdump.
  static member OptShowColor () =
    let cb opts _ =
      (BinDumpOpts.ToThis opts).ShowColor <- true
      opts
    CmdOpts.New (descr = "Show colored hexdump",
                 callback = cb, long = "--show-color")

  /// "--lift" option decides whether to show LowUIR of excutable sections.
  static member OptShowLowUIR () =
    let cb opts _ =
      (BinDumpOpts.ToThis opts).ShowLowUIR <- true
      opts
    CmdOpts.New (descr = "Show LowUIR of excutable sections",
                 callback = cb, long = "--lift")

  static member OptTransOptimization () =
    let cb opts _ =
      (BinDumpOpts.ToThis opts).DoOptimization <- Optimize
      opts
    CmdOpts.New (descr = "Perform bblock optimization for IL",
                 callback = cb, long = "--optimize")

  static member OptRawBinary () =
    let cb opts _ =
      (BinDumpOpts.ToThis opts).AutoDetect <- false
      opts
    CmdOpts.New (descr = "Turn off file format detection",
                 callback = cb, long = "--raw-binary")

[<RequireQualifiedAccess>]
module Cmd =
  let spec: BinDumpOpts FsOptParse.Option list =
    [ CmdOpts.New (descr = "[General options]", dummy = true)
      CmdOpts.New (descr = "", dummy = true)

      BinDumpOpts.OptHelp ()
      CmdOpts.OptVerbose ()
      BinDumpOpts.OptISA ()
      BinDumpOpts.OptBaseAddr ()

      CmdOpts.New (descr = "", dummy = true)
      CmdOpts.New (descr = "[Input Configuration]", dummy = true)
      CmdOpts.New (descr = "", dummy = true)

      BinDumpOpts.OptInputHexString ()
      BinDumpOpts.OptArchMode ()
      BinDumpOpts.OptRawBinary ()

      CmdOpts.New (descr = "", dummy = true)
      CmdOpts.New (descr = "[Output Configuration]", dummy = true)
      CmdOpts.New (descr = "", dummy = true)

      BinDumpOpts.OptATTSyntax ()
      BinDumpOpts.OptDumpSection ()
      BinDumpOpts.OptOnlyDisasm ()
      BinDumpOpts.OptShowAddr ()
      BinDumpOpts.OptShowSymbols ()
      BinDumpOpts.OptShowWide ()
      BinDumpOpts.OptShowColor ()
      BinDumpOpts.OptShowLowUIR ()

      CmdOpts.New (descr = "", dummy = true)
      CmdOpts.New (descr = "[Optional Configuration]", dummy = true)
      CmdOpts.New (descr = "", dummy = true)

      BinDumpOpts.OptTransOptimization ()

      CmdOpts.New (descr = "", dummy = true) ]

// vim: set tw=80 sts=2 sw=2:
