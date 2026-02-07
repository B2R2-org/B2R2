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
open B2R2

/// Represents a table-like output configuration of a table. This is useful for
/// formatting the output of console applications as we often align texts in a
/// table-like shape.
type TableConfig =
  { /// The number of spaces to indent the table.
    mutable Indentation: int
    /// The number of spaces between columns.
    mutable ColumnGap: int
    /// Format of each column.
    mutable Columns: TableColumnFormat list }
with
  /// Default table configuration with two columns.
  static member DefaultTwoColumn =
    { Indentation = 0
      ColumnGap = 1
      Columns = [ RightAligned PrinterConst.ColWidth
                  LeftAligned PrinterConst.ColWidth ] }

  member private this.Render(converter, padder, renderer, lst) =
    let lastIdx = List.length this.Columns - 1
    if this.Indentation > 0 then
      String(' ', this.Indentation) |> converter |> renderer
    else
      ()
    List.zip this.Columns lst
    |> List.iteri (fun i (colfmt, s) ->
      if i > 0 && this.ColumnGap > 0 then
        String(' ', this.ColumnGap) |> converter |> renderer
      else
        ()
      let isLast = i = lastIdx
      padder colfmt isLast s |> renderer)
    Environment.NewLine |> converter |> renderer

  /// Renders a row of the table using the given renderer function.
  member this.RenderRow(strs: string list, renderer) =
    let padder (colfmt: TableColumnFormat) isLast (s: string) =
      colfmt.Pad(s, isLast)
    this.Render(id, padder, renderer, strs)

  /// Renders a row of the table using the given renderer function.
  member this.RenderRow(css: ColoredString list, renderer) =
    let converter (s: string) = ColoredString(NoColor, s)
    let padder (colfmt: TableColumnFormat) isLast (s: ColoredString) =
      colfmt.Pad(s, isLast)
    this.Render(converter, padder, renderer, css)

  member this.RenderRow(oss: OutString list, renderer) =
    let converter (s: string) = OutputNormal s
    let padder (colfmt: TableColumnFormat) isLast (s: OutString) =
      colfmt.Pad(s, isLast)
    this.Render(converter, padder, renderer, oss)

/// Represents a column of a table with a specified width in bytes (# of chars).
and TableColumnFormat =
  | RightAligned of width: int
  | LeftAligned of width: int
with
  /// Pads the given string according to the column format.
  member this.Pad(s: string, isLast) =
    match this with
    | RightAligned width -> s.PadLeft width
    | LeftAligned width -> if isLast then s else s.PadRight width

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
