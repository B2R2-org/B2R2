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

namespace B2R2.Core.Tests

open System
open System.IO
open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2.Logging

[<TestClass>]
type LoggingTests() =

  let nl = Environment.NewLine

  let withFilePrinter lvl (body: IPrinter -> unit) =
    let path = Path.GetTempFileName()
    let printer = new FilePrinter(path, lvl) :> IPrinter
    body printer
    printer.Dispose()
    let content = File.ReadAllText path
    File.Delete path
    content

  [<TestMethod>]
  member _.``FilePrinter keeps normal and error output in call order``() =
    let content =
      withFilePrinter LogLevel.L2 (fun p ->
        p.PrintLine("normal1", LogLevel.L2)
        p.PrintErrorLine "boom"
        p.PrintLine("normal2", LogLevel.L2))
    let expected = "normal1" + nl + "[*] Error: boom" + nl + "normal2" + nl
    Assert.AreEqual<string>(expected, content)

  [<TestMethod>]
  member _.``Errors are shown even when the log level is quiet``() =
    let content =
      withFilePrinter LogLevel.L1 (fun p ->
        p.PrintLine("normal", LogLevel.L2)
        p.PrintErrorLine "err")
    Assert.AreEqual<string>("[*] Error: err" + nl, content)

  [<TestMethod>]
  member _.``Verbose messages are gated by the log level``() =
    let content =
      withFilePrinter LogLevel.L2 (fun p ->
        p.PrintLine("info", LogLevel.L3)
        p.PrintLine("norm", LogLevel.L2))
    Assert.AreEqual<string>("norm" + nl, content)

  [<TestMethod>]
  member _.``PrintError does not append a trailing newline``() =
    let content =
      withFilePrinter LogLevel.L2 (fun p ->
        p.PrintError "a"
        p.PrintError "b")
    Assert.AreEqual<string>("[*] Error: a[*] Error: b", content)

  [<TestMethod>]
  member _.``ConsolePrinter routes normal output to stdout only``() =
    let origOut, origErr = Console.Out, Console.Error
    let sbOut, sbErr = new StringWriter(), new StringWriter()
    Console.SetOut sbOut
    Console.SetError sbErr
    try
      let p = new ConsolePrinter(LogLevel.L2) :> IPrinter
      p.PrintLine("hello", LogLevel.L2)
      p.PrintErrorLine "bad"
      p.Dispose()
    finally
      Console.SetOut origOut
      Console.SetError origErr
    Assert.AreEqual<string>("hello" + nl, sbOut.ToString())
    Assert.AreEqual<string>("[*] Error: bad" + nl, sbErr.ToString())
