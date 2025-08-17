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

namespace B2R2.RearEnd.Utils

open System

/// <summary>
/// Represents a printer interface. It is recommended to use this interface
/// instead of language primitives, such as <c>System.Console</c> or
/// <c>printfn</c>.
/// </summary>
[<Interface>]
type IPrinter =
  /// Prints out the given string.
  abstract Print: s: string -> unit

  /// Prints out the given ColoredString.
  abstract Print: cs: ColoredString -> unit

  /// Prints out the given OutString.
  abstract Print: os: OutString -> unit

  /// Prints out the formatted string.
  abstract Print: string * [<ParamArray>] args: obj[] -> unit

  /// Prints out the given string as an error message, meaning that it will be
  /// printed with a certain prefix (e.g., "[*] Error: ") and newline at the
  /// end.
  abstract PrintError: s: string -> unit

  /// Prints out the given ColoredString as an error message, meaning that it
  /// will be printed with a certain prefix (e.g., "[*] Error: ") and newline at
  /// the end.
  abstract PrintError: cs: ColoredString -> unit

  /// Prints out the given OutString as an error message, meaning that it will
  /// be printed with a certain prefix (e.g., "[*] Error: ") and newline at the
  /// end.
  abstract PrintError: os: OutString -> unit

  /// Prints out the formatted string as an error message, meaning that it will
  /// be printed with a certain prefix (e.g., "[*] Error: ") and newline at the
  /// end.
  abstract PrintError: string * [<ParamArray>] args: obj[] -> unit

  /// Prints out the given string with newline.
  abstract PrintLine: s: string -> unit

  /// Prints out the given ColoredString with newline.
  abstract PrintLine: cs: ColoredString -> unit

  /// Prints out the given OutString with newline.
  abstract PrintLine: os: OutString -> unit

  /// Prints out the formatted string with newline.
  abstract PrintLine: fmt: string * [<ParamArray>] args: obj[] -> unit

  /// Prints out a newline.
  abstract PrintLine: unit -> unit

  /// Sets the spacing for table-based printing, such as PrintRow, etc.
  abstract SetTableConfig: cfg: TableConfig -> unit

  /// Sets the spacing for table-based printing, such as PrintRow, etc.
  abstract SetTableConfig: fmts: TableColumnFormat list -> unit

  /// Prints out table row for the given string list. This function only works
  /// if the table configuration set by SetTableConfig has the same number of
  /// columns as the length of the given string list.
  abstract PrintRow: string list -> unit

  /// Prints out table row for the given ColoredString list. This function only
  /// works if the table configuration set by SetTableConfig has the same number
  /// of columns as the length of the given ColoredString list.
  abstract PrintRow: ColoredString list -> unit

  /// Prints out table row for the given string list. This function only works
  /// if the table configuration set by SetTableConfig has the same number of
  /// columns as the length of the given OutString list.
  abstract PrintRow: OutString list -> unit

  /// Prints out the section title.
  abstract PrintSectionTitle: string -> unit

  /// Prints out the subsection title.
  abstract PrintSubsectionTitle: string -> unit

  /// Prints out the subsubsection title.
  abstract PrintSubsubsectionTitle: string -> unit

  /// Flushes out everything.
  abstract Flush: unit -> unit

  static member (<==) (pr: IPrinter, cfg: TableConfig) =
    pr.SetTableConfig cfg
    pr

  static member (<==) (pr: IPrinter, colfmts: TableColumnFormat list) =
    pr.SetTableConfig colfmts
    pr

  static member (<==) (pr: IPrinter, s: string) =
    pr.PrintLine s
    pr

  static member (<==) (pr: IPrinter, os: OutString) =
    pr.PrintLine os
    pr

  static member (<==) (pr: IPrinter, cs: ColoredString) =
    pr.PrintLine cs
    pr

  static member (<==) (pr: IPrinter, strs: string list) =
    pr.PrintRow strs
    pr

  static member (<==) (pr: IPrinter, css: ColoredString list) =
    pr.PrintRow css
    pr

  static member (<==) (pr: IPrinter, oss: OutString list) =
    pr.PrintRow oss
    pr

  static member (<=/) (pr: IPrinter, cfg: TableConfig) =
    pr.SetTableConfig cfg

  static member (<=/) (pr: IPrinter, colfmts: TableColumnFormat list) =
    pr.SetTableConfig colfmts

  static member (<=/) (pr: IPrinter, s: string) =
    pr.PrintLine s

  static member (<=/) (pr: IPrinter, os: OutString) =
    pr.PrintLine os

  static member (<=/) (pr: IPrinter, cs: ColoredString) =
    pr.PrintLine cs

  static member (<=/) (pr: IPrinter, strs: string list) =
    pr.PrintRow strs

  static member (<=/) (pr: IPrinter, css: ColoredString list) =
    pr.PrintRow css

  static member (<=/) (pr: IPrinter, oss: OutString list) =
    pr.PrintRow oss

  static member (<=?) (pr: IPrinter, s: string) =
    pr.PrintError s

  static member (<=?) (pr: IPrinter, os: OutString) =
    pr.PrintError os

  static member (<=?) (pr: IPrinter, cs: ColoredString) =
    pr.PrintError cs
