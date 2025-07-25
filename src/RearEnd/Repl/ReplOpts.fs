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

namespace B2R2.RearEnd.Repl

open B2R2
open B2R2.RearEnd.Utils

type ReplOpts () =
  inherit CmdOpts ()

  member val ISA = ISA Architecture.Intel with get, set
  member val ShowTemp = false with get, set

  static member private ToThis (opts: CmdOpts) =
    match opts with
    | :? ReplOpts as opts -> opts
    | _ -> failwith "Invalid Opts."

  /// "-a" or "--isa" option for specifying ISA.
  static member OptISA () =
    let cb (opts: #CmdOpts) (arg: string []) =
      (ReplOpts.ToThis opts).ISA <- ISA arg[0]; opts
    CmdOpts.New (descr = "Specify <ISA> (e.g., x86) for fat binaries",
                 extra = 1, callback = cb, short = "-a", long = "--isa")

  static member OptShowTemp () =
    let cb (opts: #CmdOpts) (_arg: string []) =
      (ReplOpts.ToThis opts).ShowTemp <- true; opts
    CmdOpts.New (descr = "Show temporary variables",
                 extra = 0, callback = cb,
                 short = "-t", long = "--show-temporary")

module ReplOpts =
  let spec: ReplOpts FsOptParse.Option list =
    [ ReplOpts.OptISA ()
      ReplOpts.OptShowTemp ()
      CmdOpts.OptVerbose ()
      CmdOpts.OptHelp () ]
