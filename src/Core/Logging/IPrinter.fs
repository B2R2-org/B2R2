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

namespace B2R2.Logging

open System
open System.Runtime.InteropServices
open B2R2

/// <summary>
/// Represents a printer interface. It is recommended to use this interface
/// instead of other language primitives, such as <c>System.Console</c> or
/// <c>printfn</c>.
/// </summary>
[<Interface>]
type IPrinter =
  inherit IDisposable

  /// Returns the current table configuration.
  abstract TableConfig: TableConfig

  /// Returns the current log level of the printer.
  abstract LogLevel: LogLevel

  /// <summary>
  /// Prints out the given string. If the optional log level `lvl` is
  /// provided, the string is printed only if the current log level is equal to
  /// or higher than `lvl`. By default, `lvl` is set to <c>LogLevel.L2</c>.
  /// </summary>
  abstract Print:
      s: string
    * [<Optional; DefaultParameterValue(LogLevel.L2)>] lvl: LogLevel
    -> unit

  /// <summary>
  /// Prints out the given ColoredString. If the optional log level `lvl` is
  /// provided, the string is printed only if the current log level is equal to
  /// or higher than `lvl`. By default, `lvl` is set to <c>LogLevel.L2</c>.
  /// </summary>
  abstract Print:
       cs: ColoredString
     * [<Optional; DefaultParameterValue(LogLevel.L2)>] lvl: LogLevel
    -> unit

  /// <summary>
  /// Prints out the given OutString. If the optional log level `lvl` is
  /// provided, the string is printed only if the current log level is equal to
  /// or higher than `lvl`. By default, `lvl` is set to <c>LogLevel.L2</c>.
  /// </summary>
  abstract Print:
       os: OutString
     * [<Optional; DefaultParameterValue(LogLevel.L2)>] lvl: LogLevel
    -> unit

  /// <summary>
  /// Prints out the given string with newline. If the optional log level `lvl`
  /// is provided, the string is printed only if the current log level is equal
  /// to or higher than `lvl`. By default, `lvl` is set to <c>LogLevel.L2</c>.
  /// </summary>
  abstract PrintLine:
       s: string
     * [<Optional; DefaultParameterValue(LogLevel.L2)>] lvl: LogLevel
    -> unit

  /// <summary>
  /// Prints out the given ColoredString with newline. If the optional log level
  /// `lvl` is provided, the string is printed only if the current log level is
  /// equal to or higher than `lvl`. By default, `lvl` is set to
  /// <c>LogLevel.L2</c>.
  /// </summary>
  abstract PrintLine:
       cs: ColoredString
     * [<Optional; DefaultParameterValue(LogLevel.L2)>] lvl: LogLevel
    -> unit

  /// <summary>
  /// Prints out the given OutString with newline. If the optional log level
  /// `lvl` is provided, the string is printed only if the current log level is
  /// equal to or higher than `lvl`. By default, `lvl` is set to
  /// <c>LogLevel.L2</c>.
  /// </summary>
  abstract PrintLine:
       os: OutString
     * [<Optional; DefaultParameterValue(LogLevel.L2)>] lvl: LogLevel
    -> unit

  /// <summary>
  /// Prints out a newline. If the optional log level `lvl` is provided, the
  /// newline is printed only if the current log level is equal to or higher
  /// than `lvl`. By default, `lvl` is set to <c>LogLevel.L2</c>.
  /// </summary>
  abstract PrintLine:
       [<Optional; DefaultParameterValue(LogLevel.L2)>] lvl: LogLevel
    -> unit

  /// Prints out a table row for the given string array of column values. This
  /// function only works if the current table configuration has the same number
  /// of columns as the length of the given string array.
  abstract PrintRow: string[] -> unit

  /// Prints out table row for the given ColoredString array of column values.
  /// This function only works if the current table configuration  has the same
  /// number of columns as the length of the given ColoredString array.
  abstract PrintRow: ColoredString[] -> unit

  /// Prints out table row for the given string array of column values. This
  /// function only works if the current table configuration has the same number
  /// of columns as the length of the given OutString array.
  abstract PrintRow: OutString[] -> unit

  /// Flushes out everything.
  abstract Flush: unit -> unit

  /// Sets the current log level of the printer. The printer will only print out
  /// messages with log level equal to or lower than the current log level. By
  /// default, the log level is set to <c>LogLevel.L2</c>.
  abstract SetLogLevel: LogLevel -> unit

  /// Prints out the given string with newline and returns the printer itself.
  /// This operator is useful for chaining multiple printing operations.
  static member (<==) (pr: IPrinter, s: string) =
    pr.PrintLine s
    pr

  /// Prints out the given OutString with newline and returns the printer
  /// itself. This operator is useful for chaining multiple printing operations.
  static member (<==) (pr: IPrinter, os: OutString) =
    pr.PrintLine os
    pr

  /// Prints out the given ColoredString with newline and returns the printer
  /// itself. This operator is useful for chaining multiple printing operations.
  static member (<==) (pr: IPrinter, cs: ColoredString) =
    pr.PrintLine cs
    pr

  /// Prints out the given string array as a table row and returns the printer
  /// itself. This operator is useful for chaining multiple printing operations.
  static member (<==) (pr: IPrinter, strs: string[]) =
    pr.PrintRow strs
    pr

  /// Prints out the given ColoredString array as a table row and returns the
  /// printer itself. This operator is useful for chaining multiple printing
  /// operations.
  static member (<==) (pr: IPrinter, css: ColoredString[]) =
    pr.PrintRow css
    pr

  /// Prints out the given OutString array as a table row and returns the
  /// printer itself. This operator is useful for chaining multiple printing
  /// operations.
  static member (<==) (pr: IPrinter, oss: OutString[]) =
    pr.PrintRow oss
    pr

  /// Prints out the given string with newline.
  static member (<=/) (pr: IPrinter, s: string) =
    pr.PrintLine s

  /// Prints out the given OutString with newline.
  static member (<=/) (pr: IPrinter, os: OutString) =
    pr.PrintLine os

  /// Prints out the given ColoredString with newline.
  static member (<=/) (pr: IPrinter, cs: ColoredString) =
    pr.PrintLine cs

  /// Prints out the given string array as a table row.
  static member (<=/) (pr: IPrinter, strs: string[]) =
    pr.PrintRow strs

  /// Prints out the given ColoredString array as a table row.
  static member (<=/) (pr: IPrinter, css: ColoredString[]) =
    pr.PrintRow css

  /// Prints out the given OutString array as a table row.
  static member (<=/) (pr: IPrinter, oss: OutString[]) =
    pr.PrintRow oss

  /// Prints out the given string as an error message.
  static member (<=?) (pr: IPrinter, s: string) =
    pr.PrintLine(s, LogLevel.L1)

  /// Prints out the given OutString as an error message.
  static member (<=?) (pr: IPrinter, os: OutString) =
    pr.PrintLine(os, LogLevel.L1)

  /// Prints out the given ColoredString as an error message.
  static member (<=?) (pr: IPrinter, cs: ColoredString) =
    pr.PrintLine(cs, LogLevel.L1)
