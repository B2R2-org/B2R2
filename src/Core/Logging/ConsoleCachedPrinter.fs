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

  let mutable myLevel = myLevel

  let mycfg = TableConfig.DefaultTwoColumn()

  let cache = StringBuilder()

  let errorPrefix = Severity.toPrefix Severity.Error

  let flush () =
    cache.ToString() |> Console.Write
    cache.Clear() |> ignore

  let add (s: string) =
    cache.Append(s) |> ignore
    if cache.Length <= PrinterConst.CacheLimit then ()
    else flush ()

  (* Diagnostics go straight to stderr instead of into the cache, so that
     redirecting stdout does not swallow them. Whatever is queued is flushed
     first, or it would surface after the message it came before. *)
  let addError (s: string) =
    flush ()
    Console.Error.Write s

  let writeDiag severity (s: string) =
    if Severity.isShownAt myLevel severity then
      Severity.toPrefix severity + s |> addError
    else
      ()

  let writeDiagLine severity (s: string) =
    if Severity.isShownAt myLevel severity then
      Severity.toPrefix severity + s + Environment.NewLine |> addError
    else
      ()

  new() = new ConsoleCachedPrinter(LogLevel.L2)

  interface IPrinter with
    member _.TableConfig with get() = mycfg

    member _.LogLevel with get() = myLevel

    member _.Dispose() = ()

    member _.Print(s: string, lvl) =
      if lvl <= myLevel then add s else ()

    member this.Print(cs: ColoredString, lvl) =
      if lvl <= myLevel then (this :> IPrinter).Print(cs.ToString(), lvl)
      else ()

    member this.Print(os: OutString, lvl) =
      if lvl <= myLevel then (this :> IPrinter).Print(os.ToString(), lvl)
      else ()

    member _.PrintLine(s: string, lvl) =
      if lvl <= myLevel then s + Environment.NewLine |> add else ()

    member _.PrintLine(cs: ColoredString, lvl) =
      if lvl <= myLevel then cs.ToString() + Environment.NewLine |> add
      else ()

    member _.PrintLine(os: OutString, lvl) =
      if lvl <= myLevel then os.ToString() + Environment.NewLine |> add
      else ()

    member _.PrintLine(lvl) =
      if lvl <= myLevel then add Environment.NewLine
      else ()

    member _.PrintRow(strs: string[]) =
      if myLevel >= LogLevel.L2 then mycfg.RenderRow(strs, add)
      else ()

    member _.PrintRow(css: ColoredString[]) =
      if myLevel >= LogLevel.L2 then
        let renderer (cs: ColoredString) = cs.ToString() |> add
        mycfg.RenderRow(css, renderer)
      else
        ()

    member _.PrintRow(oss: OutString[]) =
      if myLevel >= LogLevel.L2 then
        let renderer (os: OutString) = os.ToString() |> add
        mycfg.RenderRow(oss, renderer)
      else
        ()

    member _.PrintWarn(s: string) = writeDiag Severity.Warning s

    member _.PrintWarnLine(s: string) = writeDiagLine Severity.Warning s

    member _.PrintError(s: string) = writeDiag Severity.Error s

    member _.PrintError(cs: ColoredString) =
      errorPrefix + cs.ToString() |> addError

    member _.PrintError(os: OutString) =
      errorPrefix + os.ToString() |> addError

    member _.PrintErrorLine(s: string) = writeDiagLine Severity.Error s

    member _.PrintErrorLine(cs: ColoredString) =
      errorPrefix + cs.ToString() + Environment.NewLine |> addError

    member _.PrintErrorLine(os: OutString) =
      errorPrefix + os.ToString() + Environment.NewLine |> addError

    member _.Flush() = flush ()

    member _.SetLogLevel(lvl) =
      myLevel <- lvl