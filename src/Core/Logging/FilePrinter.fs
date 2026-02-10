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

open System.IO
open B2R2

/// Represents a printer that writes log messages to a file. This printer
/// immediately flushes out all the strings to the file whenever a log method is
/// called.
type FilePrinter(filePath, myLevel: LogLevel) =

  let mycfg = TableConfig.DefaultTwoColumn()

  let fs = File.CreateText(filePath, AutoFlush = true)

  let errorPrefix = "[*] Error: "

  let printError s = fs.WriteLine(errorPrefix + s)

  new(filePath) = new FilePrinter(filePath, LogLevel.L2)

  interface IPrinter with
    member _.TableConfig with get() = mycfg

    member _.Dispose() = fs.Dispose()

    member _.Print(s: string, lvl) =
      if lvl = LogLevel.L1 then printError s
      elif lvl <= myLevel then fs.Write s
      else ()

    member _.Print(cs: ColoredString, lvl: LogLevel) =
      if lvl = LogLevel.L1 then printError (cs.ToString())
      elif lvl <= myLevel then fs.Write(cs.ToString())
      else ()

    member _.Print(os: OutString, lvl: LogLevel) =
      if lvl = LogLevel.L1 then printError (os.ToString())
      elif lvl <= myLevel then fs.Write(os.ToString())
      else ()

    member _.PrintLine(s: string, lvl) =
      if lvl = LogLevel.L1 then printError s
      elif lvl <= myLevel then fs.WriteLine s
      else ()

    member _.PrintLine(cs: ColoredString, lvl) =
      if lvl = LogLevel.L1 then printError (cs.ToString())
      elif lvl <= myLevel then fs.WriteLine(cs.ToString())
      else ()

    member _.PrintLine(os: OutString, lvl) =
      if lvl = LogLevel.L1 then printError (os.ToString())
      elif lvl <= myLevel then fs.WriteLine(os.ToString())
      else ()

    member _.PrintLine(lvl) =
      if lvl = LogLevel.L1 then printError ""
      elif lvl <= myLevel then fs.WriteLine()
      else ()

    member _.PrintRow(strs: string[]) =
      if myLevel >= LogLevel.L2 then
        let renderer (s: string) = fs.Write s
        mycfg.RenderRow(strs, renderer)
      else
        ()

    member _.PrintRow(css: ColoredString[]) =
      if myLevel >= LogLevel.L2 then
        let renderer (cs: ColoredString) = cs.ToString() |> fs.Write
        mycfg.RenderRow(css, renderer)
      else
        ()

    member _.PrintRow(oss: OutString[]) =
      if myLevel >= LogLevel.L2 then
        let renderer (os: OutString) = os.ToString() |> fs.Write
        mycfg.RenderRow(oss, renderer)
      else
        ()

    member _.Flush() = ()
