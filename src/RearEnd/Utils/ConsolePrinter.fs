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

/// Represents a printer that simply prints out strings to console whenever a
/// print method is called. This printer does not perform any caching, so it
/// immediately flushes out all the strings to console.
type ConsolePrinter() =

  let mutable indentation = PrinterConst.Indentation

  let mutable columnGap = 0

  let mutable columnFormats = []

  /// Sets the color.
  let setColor col =
    match col with
    | NoColor ->
      Console.ResetColor()
    | Red ->
      Console.ForegroundColor <- ConsoleColor.Red
    | Green ->
      Console.ForegroundColor <- ConsoleColor.Green
    | Yellow ->
      Console.ForegroundColor <- ConsoleColor.Yellow
    | Blue ->
      Console.ForegroundColor <- ConsoleColor.Blue
    | DarkCyan ->
      Console.ForegroundColor <- ConsoleColor.DarkCyan
    | DarkYellow ->
      Console.ForegroundColor <- ConsoleColor.DarkYellow
    | RedHighlight ->
      Console.ForegroundColor <- ConsoleColor.Red
      Console.BackgroundColor <- ConsoleColor.Red
    | GreenHighlight ->
      Console.ForegroundColor <- ConsoleColor.Green
      Console.BackgroundColor <- ConsoleColor.Green

  let renderer (col: Color) (s: string) =
    setColor col
    Console.Write s

  let printErrorPrefix () =
    ColoredString()
      .Add(NoColor, "[")
      .Add(Red, "*")
      .Add(NoColor, "] ")
      .Add(Red, "Error")
      .Add(NoColor, ": ")
      .Render(renderer)

  let printErrorSuffix () =
    Console.WriteLine()

  interface IPrinter with
    member _.Print(s: string) =
      Console.Write s

    member _.Print(cs: ColoredString) =
      cs.Render(renderer)

    member _.Print(os: OutString) =
      match os with
      | OutputNormal s -> Console.Write s
      | OutputColored cs -> cs.Render(renderer)
      | OutputNewLine -> Console.WriteLine()

    member _.Print(s: string, [<ParamArray>] args) =
      Console.Write(s, args)

    member _.PrintError(s: string) =
      printErrorPrefix ()
      Console.WriteLine s
      printErrorSuffix ()

    member _.PrintError(cs: ColoredString) =
      printErrorPrefix ()
      cs.Render(renderer)
      printErrorSuffix ()

    member _.PrintError(os: OutString) =
      printErrorPrefix ()
      match os with
      | OutputNormal s -> Console.WriteLine s
      | OutputColored cs -> cs.Render(renderer)
      | OutputNewLine -> Console.WriteLine()
      printErrorSuffix ()

    member _.PrintError(s: string, [<ParamArray>] args) =
      printErrorPrefix ()
      Console.WriteLine(s, args)
      printErrorSuffix ()

    member _.PrintLine(s: string) =
      Console.WriteLine(s)

    member _.PrintLine(cs: ColoredString) =
      cs.Render(renderer)
      Console.WriteLine()

    member _.PrintLine(os: OutString) =
      match os with
      | OutputNormal s -> Console.WriteLine s
      | OutputColored cs -> cs.Render(renderer); Console.WriteLine()
      | OutputNewLine -> Console.WriteLine()

    member _.PrintLine(fmt: string, [<ParamArray>] args) =
      Console.WriteLine(fmt, args)

    member _.PrintLine() =
      Console.WriteLine()

    member _.SetTableConfig(cfg: TableConfig) =
      indentation <- cfg.Indentation
      columnGap <- cfg.ColumnGap
      columnFormats <- cfg.Columns

    member _.SetTableConfig(fmts: TableColumnFormat list) =
      columnFormats <- fmts

    member _.PrintRow(strs: string list) =
      let lastIdx = List.length columnFormats - 1
      if indentation > 0 then Console.Write(String(' ', indentation)) else ()
      List.zip columnFormats strs
      |> List.iteri (fun i (colfmt, s) ->
        if i > 0 && columnGap > 0 then Console.Write(String(' ', columnGap))
        else ()
        let isLast = i = lastIdx
        match colfmt with
        | RightAligned width -> s.PadLeft width |> Console.Write
        | LeftAligned width ->
          if isLast then Console.Write s
          else s.PadRight width |> Console.Write)
      Console.WriteLine()

    member _.PrintRow(css: ColoredString list) =
      let lastIdx = List.length columnFormats - 1
      if indentation > 0 then Console.Write(String(' ', indentation)) else ()
      List.zip columnFormats css
      |> List.iteri (fun i (colfmt, cs) ->
        if i > 0 && columnGap > 0 then Console.Write(String(' ', columnGap))
        else ()
        let isLast = i = lastIdx
        colfmt.Pad(cs, isLast).Render(renderer))
      Console.WriteLine()

    member _.PrintRow(oss: OutString list) =
      let lastIdx = List.length columnFormats - 1
      if indentation > 0 then Console.Write(String(' ', indentation)) else ()
      List.zip columnFormats oss
      |> List.iteri (fun i (colfmt, os) ->
        if i > 0 && columnGap > 0 then Console.Write(String(' ', columnGap))
        else ()
        let isLast = i = lastIdx
        colfmt.Pad(os, isLast).Render(renderer))
      Console.WriteLine()

    member this.PrintSectionTitle title =
      ColoredString().Add(Red, "# ").Add(NoColor, title).Render(renderer)
      (this :> IPrinter).PrintLine()

    member this.PrintSubsectionTitle(str: string) =
      (this :> IPrinter).PrintLine("    - " + str)

    member this.PrintSubsubsectionTitle(str: string) =
      (this :> IPrinter).PrintLine("         * " + str)

    member _.Flush() = ()
