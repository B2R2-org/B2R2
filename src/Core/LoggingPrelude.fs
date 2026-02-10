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
  let inline eprintf fmt =
    Printf.kprintf (fun message ->
      Log.Out.Print(message, LogLevel.L1)
    ) fmt

  /// Logs an error message with a newline.
  let inline eprintfn fmt =
    Printf.kprintf (fun message ->
      Log.Out.PrintLine(message, LogLevel.L1)
    ) fmt

  /// Logs a colored error string without formatting.
  let inline eprintc (cs: ColoredString) =
    Log.Out.Print(cs, LogLevel.L1)

  /// Logs a colored error string with a newline without formatting.
  let inline eprintcn (cs: ColoredString) =
    Log.Out.PrintLine(cs, LogLevel.L1)

  /// Logs an error in OutString.
  let inline eprinto (os: OutString) =
    Log.Out.Print(os, LogLevel.L1)

  /// Logs an error in OutString with a newline.
  let inline eprinton (os: OutString) =
    Log.Out.PrintLine(os, LogLevel.L1)

  /// Logs an error string without formatting.
  let inline eprints (str: string) =
    Log.Out.Print(str, LogLevel.L1)

  /// Logs an error string with a newline without formatting.
  let inline eprintsn (str: string) =
    Log.Out.PrintLine(str, LogLevel.L1)

  /// Logs a normal message.
  let inline printf fmt =
    Printf.kprintf (fun message ->
      Log.Out.Print(message, LogLevel.L2)
    ) fmt

  /// Logs a normal message with a newline.
  let inline printfn fmt =
    Printf.kprintf (fun message ->
      Log.Out.PrintLine(message, LogLevel.L2)
    ) fmt

  /// Logs a normal colored string without formatting.
  let inline printc (cs: ColoredString) =
    Log.Out.Print(cs, LogLevel.L2)

  /// Logs a normal colored string with a newline without formatting.
  let inline printcn (cs: ColoredString) =
    Log.Out.PrintLine(cs, LogLevel.L2)

  /// Logs a normal array of colored strings as a table row.
  let inline printcr (css: ColoredString[]) =
    Log.Out.PrintRow(css)

  /// Logs a normal OutString.
  let inline printo (os: OutString) =
    Log.Out.Print(os, LogLevel.L2)

  /// Logs a normal OutString with a newline.
  let inline printon (os: OutString) =
    Log.Out.PrintLine(os, LogLevel.L2)

  /// Logs a normal array of OutStrings as a table row.
  let inline printor (oss: OutString[]) =
    Log.Out.PrintRow(oss)

  /// Logs a normal string without formatting.
  let inline prints (str: string) =
    Log.Out.Print(str, LogLevel.L2)

  /// Logs a normal string with a newline without formatting.
  let inline printsn (str: string) =
    Log.Out.PrintLine(str, LogLevel.L2)

  /// Logs a normal array of strings as a table row.
  let inline printsr (strs: string[]) =
    Log.Out.PrintRow(strs)

  /// Logs an informational message.
  let inline iprintf fmt =
    Printf.kprintf (fun message ->
      Log.Out.Print(message, LogLevel.L3)
    ) fmt

  /// Logs an informational message with a newline.
  let inline iprintfn fmt =
    Printf.kprintf (fun message ->
      Log.Out.PrintLine(message, LogLevel.L3)
    ) fmt

  /// Logs an informational colored string without formatting.
  let inline iprintc (cs: ColoredString) =
    Log.Out.Print(cs, LogLevel.L3)

  /// Logs an informational colored string with a newline without formatting.
  let inline iprintcn (cs: ColoredString) =
    Log.Out.PrintLine(cs, LogLevel.L3)

  /// Logs an informational OutString.
  let inline iprinto (os: OutString) =
    Log.Out.Print(os, LogLevel.L3)

  /// Logs an informational OutString with a newline.
  let inline iprinton (os: OutString) =
    Log.Out.PrintLine(os, LogLevel.L3)

  /// Logs an informational string without formatting.
  let inline iprints (str: string) =
    Log.Out.Print(str, LogLevel.L3)

  /// Logs an informational string with a newline without formatting.
  let inline iprintsn (str: string) =
    Log.Out.PrintLine(str, LogLevel.L3)

  /// Logs a debug message.
  let inline dprintf fmt =
    Printf.kprintf (fun message ->
      Log.Out.Print(message, LogLevel.L4)
    ) fmt

  /// Logs a debug message with a newline.
  let inline dprintfn fmt =
    Printf.kprintf (fun message ->
      Log.Out.PrintLine(message, LogLevel.L4)
    ) fmt

  /// Logs a colored debug string without formatting.
  let inline dprintc (cs: ColoredString) =
    Log.Out.Print(cs, LogLevel.L4)

  /// Logs a colored debug string with a newline without formatting.
  let inline dprintcn (cs: ColoredString) =
    Log.Out.PrintLine(cs, LogLevel.L4)

  /// Logs a debug OutString.
  let inline dprinto (os: OutString) =
    Log.Out.Print(os, LogLevel.L4)

  /// Logs a debug OutString with a newline.
  let inline dprinton (os: OutString) =
    Log.Out.PrintLine(os, LogLevel.L4)

  /// Logs a debug string without formatting.
  let inline dprints (str: string) =
    Log.Out.Print(str, LogLevel.L4)

  /// Logs a debug string with a newline without formatting.
  let inline dprintsn (str: string) =
    Log.Out.PrintLine(str, LogLevel.L4)
