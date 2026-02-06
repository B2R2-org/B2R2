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
open System.IO

/// Represents a printer that writes log messages to a file. This printer
/// immediately flushes out all the strings to the file whenever a log method is
/// called.
type FilePrinter(filePath, myLevel: LogLevel) =

  let mycfg = TableConfig.DefaultTwoColumn

  let fs = File.CreateText(filePath, AutoFlush = true)

  let errorPrefix = "[*] Error: "

  new(filePath) = new FilePrinter(filePath, LogLevel.L2)

  interface IPrinter with
    member _.Dispose() = fs.Dispose()

    member _.Print(s: string, lvl) =
      if lvl <= myLevel then fs.Write s
      else ()

    member this.Print(cs: ColoredString, lvl: LogLevel) =
      (this :> IPrinter).Print(cs.ToString(), lvl)

    member this.Print(os: OutString, lvl: LogLevel) =
      (this :> IPrinter).Print(os.ToString(), lvl)

    member _.Print(s: string, [<ParamArray>] args: obj[]) = fs.Write(s, args)

    member _.PrintError(s: string) = fs.WriteLine(errorPrefix + s)

    member _.PrintError(cs: ColoredString) =
      fs.WriteLine(errorPrefix + cs.ToString())

    member _.PrintError(os: OutString) =
      fs.WriteLine(errorPrefix + os.ToString())

    member _.PrintError(fmt: string, [<ParamArray>] args) =
      fs.WriteLine(errorPrefix + fmt, args)

    member _.PrintLine(s: string, lvl) =
      if lvl <= myLevel then fs.WriteLine s
      else ()

    member _.PrintLine(cs: ColoredString, lvl) =
      if lvl <= myLevel then fs.WriteLine(cs.ToString())
      else ()

    member _.PrintLine(os: OutString, lvl) =
      if lvl <= myLevel then fs.WriteLine(os.ToString())
      else ()

    member _.PrintLine(fmt: string, [<ParamArray>] args: obj[]) =
      fs.WriteLine(fmt, args)

    member _.PrintLine(lvl) =
      if lvl <= myLevel then fs.WriteLine()
      else ()

    member _.SetTableConfig(cfg: TableConfig) =
      mycfg.Indentation <- cfg.Indentation
      mycfg.ColumnGap <- cfg.ColumnGap
      mycfg.Columns <- cfg.Columns

    member _.SetTableConfig(fmts: TableColumnFormat list) =
      mycfg.Columns <- fmts

    member _.PrintRow(strs: string list) =
      let renderer (s: string) = fs.Write s
      mycfg.RenderRow(strs, renderer)

    member _.PrintRow(css: ColoredString list) =
      let renderer (cs: ColoredString) = cs.ToString() |> fs.Write
      mycfg.RenderRow(css, renderer)

    member _.PrintRow(oss: OutString list) =
      let renderer (os: OutString) = os.ToString() |> fs.Write
      mycfg.RenderRow(oss, renderer)

    member _.PrintSectionTitle title = "# " + title |> fs.WriteLine

    member _.PrintSubsectionTitle(str: string) = "    - " + str |> fs.WriteLine

    member _.PrintSubsubsectionTitle(str: string) =
      "         * " + str |> fs.WriteLine

    member _.Flush() = ()
