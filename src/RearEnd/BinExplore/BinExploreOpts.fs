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

namespace B2R2.RearEnd.BinExplore

open B2R2
open B2R2.RearEnd.Utils
open B2R2.FsOptParse

/// Represents cmdline options for BinExplore.
type BinExploreOpts =
  { /// IP address to bind. We can specify an IP to use to enable remote access,
    /// but we should make sure the two things:
    /// (1) Make sure we have a permission to bind to the IP address. On
    ///     Windows, we may have to run `netsh` command to enable this. For
    ///     example: netsh http add urlacl url=http://192.168.1.1:8282/
    ///     user=sangkilc
    /// (2) Make sure firewall does not block the connection.
    IP: string
    /// Host port number.
    Port: int
    /// Logging output file.
    LogFile: string
    /// ISA of the target binary. This is only meaningful for universal (FAT)
    /// binaries because BinHandle will automatically detect file format by
    /// default. When a FAT binary is given, we need to choose which ISA to use
    /// with this option.
    ISA: ISA
    /// Verbosity.
    Verbose: bool }
with
  interface IVerboseOption with
    member this.IsVerbose with get() = this.Verbose

  static member Default(isa: ISA) =
    { IP = "localhost"
      Port = 8282
      LogFile = "b2r2.log"
      ISA = isa
      Verbose = false }

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
      Opt(descr = noCol "Specify log file <name> (default: B2R2.log)",
          short = "-l", long = "--log", extra = 1,
          callback = fun opts arg -> { opts with LogFile = arg[0] })
      Opt(descr = noCol "Specify <ISA> (e.g., x86) for fat binaries",
          short = "-a", long = "--isa", extra = 1,
          callback = fun opts arg -> { opts with ISA = ISA arg[0] })
      Opt(descr = noCol "",
          dummy = true)
      Opt(descr = ColoredString().Add(NoColor, "[")
                                 .Add(DarkCyan, "Host Configuration")
                                 .Add(NoColor, "]"),
          descrPrinter = printcn,
          dummy = true)
      Opt(descr = noCol "",
          dummy = true)
      Opt(descr = noCol "Specify IP <address> (default: localhost)",
          short = "-i", long = "--ip", extra = 1,
          callback = fun opts arg -> { opts with IP = arg[0] })
      Opt(descr = noCol "Specify host port <number> (default: 8282)",
          short = "-p", long = "--port", extra = 1,
          callback = fun opts arg -> { opts with Port = int arg[0] }) ]

and Opt = CmdOpt<BinExploreOpts, ColoredString>
