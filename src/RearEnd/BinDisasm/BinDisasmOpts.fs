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

namespace B2R2.RearEnd.BinDisasm

open System
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FsOptParse
open B2R2.RearEnd.Utils

type BinDisasmOpts =
  { /// ISA.
    ISA: ISA
    /// Base address.
    BaseAddress: Addr option
    /// Input section name from command line.
    InputSecName: string option
    /// Input hexstring from command line.
    InputHexStr: byte[]
    /// Thumb mode.
    ThumbMode: bool
    /// Whether to show addresses or not.
    ShowAddress: bool
    /// Whether to show symbols or not.
    ShowSymbols: bool
    /// Whether to show LowUIR or not.
    ShowLowUIR: bool
    /// Whether to show hexdump widely or not, 32 bytes (default 16 bytes).
    ShowWide: bool
    /// Whether to show hexdump colored or not, just for files not hexstring.
    ShowColor: bool
    /// Display only disassembly.
    OnlyDisasm: bool
    /// Disassembly syntax.
    DisassemblySyntax: DisasmSyntax
    /// Perform basic block optimization or not?
    DoOptimization: bool
    /// Detect binary file format or not?
    AutoDetect: bool
    /// Verbosity.
    Verbose: bool }
with
  interface IVerboseOption with
    member this.IsVerbose with get() = this.Verbose

  static member Default =
    { ISA = ISA Architecture.Intel
      BaseAddress = None
      InputSecName = None
      InputHexStr = [||]
      ThumbMode = false
      ShowAddress = false
      ShowSymbols = true
      ShowLowUIR = false
      ShowWide = false
      ShowColor = false
      OnlyDisasm = false
      DisassemblySyntax = DefaultSyntax
      DoOptimization = false
      AutoDetect = true
      Verbose = false }

  static let cbBaseAddress opts (arg: _[]) =
    { opts with
        BaseAddress = Some(Convert.ToUInt64(arg[0], 16))
        ShowAddress = true }

  static let cbInputHexStr opts (arg: _[]) =
    { opts with InputHexStr = ByteArray.ofHexString arg[0] }

  static let cbArchMode opts (arg: string[]) =
    match arg[0].ToLowerInvariant() with
    | "thumb" -> { opts with ThumbMode = true }
    | _ -> opts

  static let cbATTSyntax opts _ =
    { opts with DisassemblySyntax = ATTSyntax }

  static let cbSection opts (arg: _[]) =
    { opts with InputSecName = Some arg[0] }

  static member Spec =
    [ Opt(descr = ColoredString().Add(NoColor, "[")
                                 .Add(DarkCyan, "General Options")
                                 .Add(NoColor, "]"),
          descrPrinter = printcn,
          dummy = true)
      Opt(descr = noCol "",
          dummy = true)
      Opt(descr = noCol "Show this usage",
          short = "-h", long = "--help",
          help = true)
      Opt(descr = noCol "Verbose mode",
          short = "-v", long = "--verbose",
          callback = fun opts _ -> { opts with Verbose = true })
      Opt(descr = noCol "Specify <ISA> (e.g., x86)",
          short = "-i", long = "--isa", extra = 1,
          callback = fun opts arg -> { opts with ISA = ISA arg[0] })
      Opt(descr = noCol "Specify the base <address> in hex (default=0)",
          short = "-r", long = "--base-addr", extra = 1,
          callback = cbBaseAddress)
      Opt(descr = noCol "",
          dummy = true)
      Opt(descr = ColoredString().Add(NoColor, "[")
                                 .Add(DarkCyan, "Input Configuration")
                                 .Add(NoColor, "]"),
          descrPrinter = printcn,
          dummy = true)
      Opt(descr = noCol "",
          dummy = true)
      Opt(descr = noCol "Specify an input <hexstring>",
          short = "-s", extra = 1,
          callback = cbInputHexStr)
      Opt(descr = noCol "Specify <operation mode> (e.g., thumb/arm)",
          short = "-m", long = "--mode", extra = 1,
          callback = cbArchMode)
      Opt(descr = noCol "Turn off file format detection",
          long = "--raw-binary",
          callback = fun opts _ -> { opts with AutoDetect = false })
      Opt(descr = noCol "",
          dummy = true)
      Opt(descr = ColoredString().Add(NoColor, "[")
                                 .Add(DarkCyan, "Output Configuration")
                                 .Add(NoColor, "]"),
          descrPrinter = printcn,
          dummy = true)
      Opt(descr = noCol "",
          dummy = true)
      Opt(descr = noCol "Use AT&T syntax for disassembling Intel instructions",
          long = "--att",
          callback = cbATTSyntax)
      Opt(descr = noCol "Display the contents of a specific section",
          short = "-S", long = "--section", extra = 1,
          callback = cbSection)
      Opt(descr = noCol "Always display disassembly for all sections.",
          long = "--only-disasm",
          callback = fun opts _ -> { opts with OnlyDisasm = true })
      Opt(descr = noCol "Show addresses of hexstring",
          long = "--show-addr",
          callback = fun opts _ -> { opts with ShowAddress = true })
      Opt(descr = noCol "Show symbols while disassembling binary",
          long = "--hide-symbols",
          callback = fun opts _ -> { opts with ShowSymbols = false })
      Opt(descr = noCol "Show hexdump with 32 bytes per line",
          long = "--show-wide",
          callback = fun opts _ -> { opts with ShowWide = true })
      Opt(descr = noCol "Show colored hexdump",
          long = "--show-color",
          callback = fun opts _ -> { opts with ShowColor = true })
      Opt(descr = noCol "Show LowUIR of excutable sections",
          long = "--lift",
          callback = fun opts _ -> { opts with ShowLowUIR = true })
      Opt(descr = noCol "",
          dummy = true)
      Opt(descr = ColoredString().Add(NoColor, "[")
                                 .Add(DarkCyan, "Optional Configuration")
                                 .Add(NoColor, "]"),
          descrPrinter = printcn,
          dummy = true)
      Opt(descr = noCol "",
          dummy = true)
      Opt(descr = noCol "Perform bblock optimization for IL",
          long = "--optimize",
          callback = fun opts _ -> { opts with DoOptimization = true }) ]

and Opt = CmdOpt<BinDisasmOpts, ColoredString>
