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

/// Provides printing utility functions used in RearEnd.
[<AutoOpen>]
module Printer =
  open B2R2
  open B2R2.Logging

  /// Prints a section title.
  let printSectionTitle (title: string) =
    let cs = ColoredString().Add(Red, "# ").Add(NoColor, title)
    Log.Out.PrintLine(cs)
    Log.Out.PrintLine()

  /// Prints a subsection title.
  let printSubsectionTitle (title: string) =
    Log.Out.PrintLine("## " + title)
    Log.Out.PrintLine()

  /// Prints a subsubsection title.
  let printSubsubsectionTitle (title: string) =
    Log.Out.PrintLine("### " + title)
    Log.Out.PrintLine()

  /// Prints a horizontal rule using the specified character.
  let private printHorizontalRuleWith ch =
    let symbol = string ch
    let widths =
      Log.Out.TableConfig.Columns
      |> Array.map (fun col ->
        match col with
        | LeftAligned w
        | RightAligned w -> w)
    for i in 0 .. widths.Length - 1 do
      let width =
        if i < widths.Length - 1 then widths[i] + Log.Out.TableConfig.ColumnGap
        else widths[i]
      let s = String.replicate width symbol
      Log.Out.Print(s)
    if widths.Length > 0 then Log.Out.PrintLine()
    else ()

  /// Prints a single horizontal rule.
  let printSingleHorizontalRule () =
    printHorizontalRuleWith '-'

  /// Prints a double horizontal rule.
  let printDoubleHorizontalRule () =
    printHorizontalRuleWith '='

  /// Sets the column formats of the table.
  let setTableColumnFormats colfmts =
    Log.Out.TableConfig.Columns <- colfmts

  /// Sets the table configuration according to the given configuration.
  let inline setTableConfig indent gap cols =
    Log.Out.TableConfig.Indentation <- indent
    Log.Out.TableConfig.ColumnGap <- gap
    Log.Out.TableConfig.Columns <- cols

  let private defaultTwoColumnConfig = TableConfig.DefaultTwoColumn()

  /// Resets the table configuration to the default two-column format.
  let resetToDefaultTwoColumnConfig () =
    setTableConfig
      defaultTwoColumnConfig.Indentation
      defaultTwoColumnConfig.ColumnGap
      defaultTwoColumnConfig.Columns

  /// Flushes the output buffer, ensuring that all pending output is written
  /// out.
  let flush () =
    Log.Out.Flush()
