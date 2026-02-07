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
open System.Text
open B2R2

/// Represents a printer that prints out non-colored strings only when the Flush
/// method is called. All the colored strings will be normalized to plain
/// strings. It will simply stack up all the output candidates before Flush is
/// called. This is useful for performance-critical applications.
type ConsoleCachedPrinter(myLevel: LogLevel) =

  let mycfg = TableConfig.DefaultTwoColumn

  let cache = StringBuilder()

  let errorPrefix = "[*] Error: "

  let flush () =
    cache.ToString() |> Console.Write
    cache.Clear() |> ignore

  let add (s: string) =
    cache.Append(s) |> ignore
    if cache.Length <= PrinterConst.CacheLimit then ()
    else flush ()

  new() = new ConsoleCachedPrinter(LogLevel.L2)

  interface IPrinter with
    member _.Dispose() = ()

    member _.Print(s: string, lvl) =
      if lvl = LogLevel.L1 then errorPrefix + s + Environment.NewLine |> add
      elif lvl <= myLevel then add s
      else ()

    member this.Print(cs: ColoredString, lvl) =
      if lvl <= myLevel then (this :> IPrinter).Print(cs.ToString(), lvl)
      else ()

    member this.Print(os: OutString, lvl) =
      if lvl <= myLevel then (this :> IPrinter).Print(os.ToString(), lvl)
      else ()

    member _.PrintLine(s: string, lvl) =
      if lvl = LogLevel.L1 then errorPrefix + s + Environment.NewLine |> add
      elif lvl <= myLevel then s + Environment.NewLine |> add
      else ()

    member _.PrintLine(cs: ColoredString, lvl) =
      if lvl = LogLevel.L1 then
        errorPrefix + cs.ToString() + Environment.NewLine |> add
      elif lvl <= myLevel then
        cs.ToString() + Environment.NewLine |> add
      else ()

    member _.PrintLine(os: OutString, lvl) =
      if lvl = LogLevel.L1 then
        errorPrefix + os.ToString() + Environment.NewLine |> add
      elif lvl <= myLevel then
        os.ToString() + Environment.NewLine |> add
      else ()

    member _.PrintLine(lvl) =
      if lvl <= myLevel then add Environment.NewLine
      else ()

    member _.SetTableConfig(cfg: TableConfig) =
      mycfg.Indentation <- cfg.Indentation
      mycfg.ColumnGap <- cfg.ColumnGap
      mycfg.Columns <- cfg.Columns

    member _.SetTableConfig(fmts: TableColumnFormat list) =
      mycfg.Columns <- fmts

    member _.PrintRow(strs: string list) =
      if myLevel >= LogLevel.L2 then mycfg.RenderRow(strs, add)
      else ()

    member _.PrintRow(css: ColoredString list) =
      if myLevel >= LogLevel.L2 then
        let renderer (cs: ColoredString) = cs.ToString() |> add
        mycfg.RenderRow(css, renderer)
      else
        ()

    member _.PrintRow(oss: OutString list) =
      if myLevel >= LogLevel.L2 then
        let renderer (os: OutString) = os.ToString() |> add
        mycfg.RenderRow(oss, renderer)
      else
        ()

    member _.PrintSectionTitle title =
      "# " + title + Environment.NewLine + Environment.NewLine |> add

    member _.PrintSubsectionTitle(str: string) =
      "    - " + str |> add
      add Environment.NewLine

    member _.PrintSubsubsectionTitle(str: string) =
      "         * " + str |> add
      add Environment.NewLine

    member _.Flush() =
      cache.ToString() |> Console.Write
      cache.Clear() |> ignore