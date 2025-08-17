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

/// Represents a table-like output configuration of a table. This is useful for
/// formatting the output of console applications as we often align texts in a
/// table-like shape.
type TableConfig =
  { /// The number of spaces to indent the table.
    Indentation: int
    /// The number of spaces between columns.
    ColumnGap: int
    /// Format of each column.
    Columns: TableColumnFormat list }
with
  /// Default table configuration with two columns.
  static member DefaultTwoColumn =
    { Indentation = 0
      ColumnGap = 1
      Columns = [ RightAligned PrinterConst.ColWidth
                  LeftAligned PrinterConst.ColWidth ] }

/// Represents a column of a table with a specified width in bytes (# of chars).
and TableColumnFormat =
  | RightAligned of width: int
  | LeftAligned of width: int
with
  /// Pads the given ColoredString according to the column format.
  member this.Pad(cs: ColoredString, isLast) =
    match this with
    | RightAligned width -> cs.PadLeft width
    | LeftAligned width -> if isLast then cs else cs.PadRight width

  /// Pads the given ColoredString according to the column format.
  member this.Pad(os: OutString, isLast) =
    match this with
    | RightAligned width -> os.PadLeft width
    | LeftAligned width -> if isLast then os else os.PadRight width
