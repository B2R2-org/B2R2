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

/// Represents a printer that simply prints out strings to console whenever a
/// print method is called. This printer does not perform any caching, so it
/// immediately flushes out all the strings to console.
type ConsolePrinter(myLevel: LogLevel) =

  let mutable myLevel = myLevel

  let mycfg = TableConfig.DefaultTwoColumn()

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
      Console.ForegroundColor <- ConsoleColor.White
      Console.BackgroundColor <- ConsoleColor.Red
    | GreenHighlight ->
      Console.ForegroundColor <- ConsoleColor.Black
      Console.BackgroundColor <- ConsoleColor.Green

  let render (w: IO.TextWriter) (cs: ColoredString) =
    cs.Render(fun col s -> setColor col; w.Write s)
    Console.ResetColor()

  let printOutString (w: IO.TextWriter) hasNewLineAtTheEnd (os: OutString) =
    match os with
    | OutputNormal s ->
      if hasNewLineAtTheEnd then w.WriteLine s
      else w.Write s
    | OutputColored cs ->
      render w cs
      if hasNewLineAtTheEnd then w.WriteLine() else ()
    | OutputNewLine ->
      w.WriteLine()

  let printErrorPrefix () =
    ColoredString()
      .Append(NoColor, "[")
      .Append(Red, "*")
      .Append(NoColor, "] ")
      .Append(Red, "Error")
      .Append(NoColor, ": ")
    |> render Console.Error

  new() = new ConsolePrinter(LogLevel.L2)

  interface IPrinter with
    member _.TableConfig with get() = mycfg

    member _.LogLevel with get() = myLevel

    member _.Dispose() = ()

    member _.Print(s: string, lvl) =
      if lvl <= myLevel then Console.Out.Write s else ()

    member _.Print(cs: ColoredString, lvl) =
      if lvl <= myLevel then render Console.Out cs else ()

    member _.Print(os: OutString, lvl) =
      if lvl <= myLevel then printOutString Console.Out false os else ()

    member _.PrintLine(s: string, lvl) =
      if lvl <= myLevel then Console.Out.WriteLine s else ()

    member _.PrintLine(cs: ColoredString, lvl) =
      if lvl <= myLevel then
        render Console.Out cs
        Console.Out.WriteLine()
      else
        ()

    member _.PrintLine(os: OutString, lvl) =
      if lvl <= myLevel then printOutString Console.Out true os else ()

    member _.PrintLine(lvl) =
      if lvl <= myLevel then Console.WriteLine()
      else ()

    member _.PrintRow(strs: string[]) =
      if myLevel >= LogLevel.L2 then
        let renderer (s: string) = Console.Write s
        mycfg.RenderRow(strs, renderer)
      else
        ()

    member _.PrintRow(css: ColoredString[]) =
      if myLevel >= LogLevel.L2 then
        let renderer (cs: ColoredString) = render Console.Out cs
        mycfg.RenderRow(css, renderer)
      else
        ()

    member _.PrintRow(oss: OutString[]) =
      if myLevel >= LogLevel.L2 then
        let renderer (os: OutString) =
          os.Render(fun col s -> setColor col; Console.Out.Write s)
          Console.ResetColor()
        mycfg.RenderRow(oss, renderer)
      else
        ()

    member _.PrintError(s: string) =
      printErrorPrefix ()
      Console.Error.Write s

    member _.PrintError(cs: ColoredString) =
      printErrorPrefix ()
      render Console.Error cs

    member _.PrintError(os: OutString) =
      printErrorPrefix ()
      printOutString Console.Error false os

    member _.PrintErrorLine(s: string) =
      printErrorPrefix ()
      Console.Error.WriteLine s

    member _.PrintErrorLine(cs: ColoredString) =
      printErrorPrefix ()
      render Console.Error cs
      Console.Error.WriteLine()

    member _.PrintErrorLine(os: OutString) =
      printErrorPrefix ()
      printOutString Console.Error true os

    member _.Flush() =
      ()

    member _.SetLogLevel(lvl) =
      myLevel <- lvl
