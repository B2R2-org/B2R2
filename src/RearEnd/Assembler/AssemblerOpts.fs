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

namespace B2R2.RearEnd.Assembler

open System
open B2R2
open B2R2.RearEnd.Utils
open B2R2.FsOptParse

type AssemblerOpts =
  { Mode: AssemblerMode
    BaseAddress: Addr
    OutFile: string option
    Verbose: bool }
with
  interface IVerboseOption with
    member this.IsVerbose with get() = this.Verbose

  static member Default =
    { Mode = GeneralMode(ISA Architecture.Intel)
      BaseAddress = 0UL
      OutFile = None
      Verbose = false }

  static member Spec =
    [ CmdOpt(descr = "Show this usage",
             help = true,
             short = "-h",
             long = "--help")
      CmdOpt(descr = "Verbose mode",
             short = "-v",
             long = "--verbose",
             callback = fun opts _ -> { opts with Verbose = true })
      CmdOpt(descr = "Take in LowUIR assembly code as input (ignore ISA)",
             short = "-l",
             long = "--lowuir",
             callback = fun opts _ ->
               { opts with Mode = AssemblerMode.ToLowUIRMode opts.Mode })
      CmdOpt(descr = "Specify <ISA> (e.g., x86) from command line",
             short = "-i",
             long = "--isa",
             extra = 1,
             callback = fun opts arg ->
               { opts with
                   Mode = AssemblerMode.ChangeISA(ISA arg[0], opts.Mode) })
      CmdOpt(descr = "Write the assembled raw binary to the given <file>",
             short = "-o",
             long = "--output",
             extra = 1,
             callback = fun opts arg -> { opts with OutFile = Some arg[0] })
      CmdOpt(descr = "Specify the base <address> in hex (default=0)",
             short = "-r",
             long = "--base-addr",
             extra = 1,
             callback = fun opts arg ->
               { opts with BaseAddress = Convert.ToUInt64(arg[0], 16) }) ]

and AssemblerMode =
  | LowUIRMode of ISA
  | GeneralMode of ISA
with
  static member ToLowUIRMode mode =
    match mode with
    | LowUIRMode isa
    | GeneralMode isa -> LowUIRMode isa

  static member ChangeISA(isa: ISA, mode) =
    match mode with
    | LowUIRMode _ -> LowUIRMode isa
    | GeneralMode _ -> GeneralMode isa
