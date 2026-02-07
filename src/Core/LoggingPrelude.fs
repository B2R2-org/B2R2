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

namespace B2R2

/// Provides convenient functions for logging.
[<AutoOpen>]
module LoggingPrelude =
  open B2R2.Logging

  /// Logs an error message.
  let eprintf fmt =
    Printf.kprintf (fun message ->
      Log.Out.Print(message, LogLevel.L1)
    ) fmt

  /// Logs an error message with a newline.
  let eprintfn fmt =
    Printf.kprintf (fun message ->
      Log.Out.PrintLine(message, LogLevel.L1)
    ) fmt

  /// Logs a colored error string without formatting.
  let eprintc (cs: ColoredString) = Log.Out.Print(cs, LogLevel.L1)

  /// Logs a colored error string with a newline without formatting.
  let eprintcn (cs: ColoredString) = Log.Out.PrintLine(cs, LogLevel.L1)

  /// Logs an error in OutString.
  let eprinto (os: OutString) = Log.Out.Print(os, LogLevel.L1)

  /// Logs an error in OutString with a newline.
  let eprinton (os: OutString) = Log.Out.PrintLine(os, LogLevel.L1)

  /// Logs an error string without formatting.
  let eprints (str: string) = Log.Out.Print(str, LogLevel.L1)

  /// Logs an error string with a newline without formatting.
  let eprintsn (str: string) = Log.Out.PrintLine(str, LogLevel.L1)

  /// Logs a normal message.
  let printf fmt =
    Printf.kprintf (fun message ->
      Log.Out.Print(message, LogLevel.L2)
    ) fmt

  /// Logs a normal message with a newline.
  let printfn fmt =
    Printf.kprintf (fun message ->
      Log.Out.PrintLine(message, LogLevel.L2)
    ) fmt

  /// Logs a normal colored string without formatting.
  let printc (cs: ColoredString) = Log.Out.Print(cs, LogLevel.L2)

  /// Logs a normal colored string with a newline without formatting.
  let printcn (cs: ColoredString) = Log.Out.PrintLine(cs, LogLevel.L2)

  /// Logs a normal list of colored strings as a table row.
  let printcr (css: ColoredString list) = Log.Out.PrintRow(css)

  /// Logs a normal OutString.
  let printo (os: OutString) = Log.Out.Print(os, LogLevel.L2)

  /// Logs a normal OutString with a newline.
  let printon (os: OutString) = Log.Out.PrintLine(os, LogLevel.L2)

  /// Logs a normal list of OutStrings as a table row.
  let printor (oss: OutString list) = Log.Out.PrintRow(oss)

  /// Logs a normal string without formatting.
  let prints (str: string) = Log.Out.Print(str, LogLevel.L2)

  /// Logs a normal string with a newline without formatting.
  let printsn (str: string) = Log.Out.PrintLine(str, LogLevel.L2)

  /// Logs a normal list of strings as a table row.
  let printsr (strs: string list) = Log.Out.PrintRow(strs)

  /// Logs an informational message.
  let iprintf fmt =
    Printf.kprintf (fun message ->
      Log.Out.Print(message, LogLevel.L3)
    ) fmt

  /// Logs an informational message with a newline.
  let iprintfn fmt =
    Printf.kprintf (fun message ->
      Log.Out.PrintLine(message, LogLevel.L3)
    ) fmt

  /// Logs an informational colored string without formatting.
  let iprintc (cs: ColoredString) = Log.Out.Print(cs, LogLevel.L3)

  /// Logs an informational colored string with a newline without formatting.
  let iprintcn (cs: ColoredString) = Log.Out.PrintLine(cs, LogLevel.L3)

  /// Logs an informational OutString.
  let iprinto (os: OutString) = Log.Out.Print(os, LogLevel.L3)

  /// Logs an informational OutString with a newline.
  let iprinton (os: OutString) = Log.Out.PrintLine(os, LogLevel.L3)

  /// Logs an informational string without formatting.
  let iprints (str: string) = Log.Out.Print(str, LogLevel.L3)

  /// Logs an informational string with a newline without formatting.
  let iprintsn (str: string) = Log.Out.PrintLine(str, LogLevel.L3)

  /// Logs a debug message.
  let dprintf fmt =
    Printf.kprintf (fun message ->
      Log.Out.Print(message, LogLevel.L4)
    ) fmt

  /// Logs a debug message with a newline.
  let dprintfn fmt =
    Printf.kprintf (fun message ->
      Log.Out.PrintLine(message, LogLevel.L4)
    ) fmt

  /// Logs a colored debug string without formatting.
  let dprintc (cs: ColoredString) = Log.Out.Print(cs, LogLevel.L4)

  /// Logs a colored debug string with a newline without formatting.
  let dprintcn (cs: ColoredString) = Log.Out.PrintLine(cs, LogLevel.L4)

  /// Logs a debug OutString.
  let dprinto (os: OutString) = Log.Out.Print(os, LogLevel.L4)

  /// Logs a debug OutString with a newline.
  let dprinton (os: OutString) = Log.Out.PrintLine(os, LogLevel.L4)

  /// Logs a debug string without formatting.
  let dprints (str: string) = Log.Out.Print(str, LogLevel.L4)

  /// Logs a debug string with a newline without formatting.
  let dprintsn (str: string) = Log.Out.PrintLine(str, LogLevel.L4)
