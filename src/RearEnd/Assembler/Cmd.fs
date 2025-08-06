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

type AssemblerMode =
  | LowUIRMode of ISA
  | GeneralMode of ISA

module private AssemblerMode =
  let toLowUIRMode = function
    | LowUIRMode isa
    | GeneralMode isa -> LowUIRMode isa

  let changeISA isa = function
    | LowUIRMode _ -> LowUIRMode isa
    | GeneralMode _ -> GeneralMode isa

type AssemblerOpts() =
  inherit CmdOpts()

  /// Mode
  member val Mode = GeneralMode (ISA Architecture.Intel) with get, set

  /// Base address
  member val BaseAddress: Addr = 0UL with get, set

  static member private ToThis(opts: CmdOpts) =
    match opts with
    | :? AssemblerOpts as opts -> opts
    | _ -> failwith "Invalid Opts."

  /// "-l" or "--lowuir" option for LowUIR mode
  static member OptLowUIR() =
    let cb (opts: #CmdOpts) (_arg: string []) =
      (AssemblerOpts.ToThis opts).Mode <-
        AssemblerMode.toLowUIRMode (AssemblerOpts.ToThis opts).Mode
      opts
    CmdOpts.New(descr = "Take in LowUIR assembly code as input (ignore ISA)",
                callback = cb, short = "-l", long = "--lowuir")

  /// "-i" or "--isa" option for specifying ISA.
  static member OptISA() =
    let cb (opts: #CmdOpts) (arg: string []) =
      (AssemblerOpts.ToThis opts).Mode <-
        AssemblerMode.changeISA (ISA arg[0])
          (AssemblerOpts.ToThis opts).Mode
      opts
    CmdOpts.New(descr = "Specify <ISA> (e.g., x86) from command line",
                extra = 1, callback = cb, short = "-i", long = "--isa")

  /// "-r" or "--base-addr" option for specifying a base address.
  static member OptBaseAddr() =
    let cb (opts: #CmdOpts) (arg: string []) =
      (AssemblerOpts.ToThis opts).BaseAddress <- Convert.ToUInt64(arg[0], 16)
      opts
    CmdOpts.New(descr = "Specify the base <address> in hex (default=0)",
                extra = 1, callback = cb, short = "-r", long = "--base-addr")

module Cmd =
  let spec: AssemblerOpts FsOptParse.Option list =
    [ CmdOpts.OptVerbose()
      CmdOpts.OptHelp()
      AssemblerOpts.OptLowUIR()
      AssemblerOpts.OptISA()
      AssemblerOpts.OptBaseAddr() ]
