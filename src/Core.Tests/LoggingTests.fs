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

  /// Runs the body against a cached printer with both console streams
  /// captured, then flushes it and returns what each stream received. The body
  /// also gets the stdout writer, so that it can observe the cache mid-run.
  let withCachedPrinter (body: IPrinter -> StringWriter -> unit) =
    let origOut, origErr = Console.Out, Console.Error
    let sbOut, sbErr = new StringWriter(), new StringWriter()
    Console.SetOut sbOut
    Console.SetError sbErr
    try
      let printer = new ConsoleCachedPrinter(LogLevel.L2) :> IPrinter
      body printer sbOut
      printer.Flush()
      printer.Dispose()
    finally
      Console.SetOut origOut
      Console.SetError origErr
    sbOut.ToString(), sbErr.ToString()

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

  (* Caching used to put errors into the stdout cache along with everything
     else, so redirecting stdout swallowed them. *)
  [<TestMethod>]
  member _.``ConsoleCachedPrinter routes error output to stderr``() =
    let out, err =
      withCachedPrinter (fun p _ ->
        p.PrintLine("normal", LogLevel.L2)
        p.PrintErrorLine "boom")
    Assert.AreEqual<string>("normal" + nl, out)
    Assert.AreEqual<string>("[*] Error: boom" + nl, err)

  (* An error bypasses the cache, so whatever is queued has to be flushed first
     or it would surface after the error it came before. *)
  [<TestMethod>]
  member _.``ConsoleCachedPrinter flushes the cache before an error``() =
    let pending, flushed = ref "unset", ref "unset"
    let out, _ =
      withCachedPrinter (fun p sbOut ->
        p.PrintLine("normal", LogLevel.L2)
        pending.Value <- sbOut.ToString()
        p.PrintErrorLine "boom"
        flushed.Value <- sbOut.ToString())
    Assert.AreEqual<string>("", pending.Value)
    Assert.AreEqual<string>("normal" + nl, flushed.Value)
    Assert.AreEqual<string>("normal" + nl, out)

  [<TestMethod>]
  member _.``Warnings carry their own prefix``() =
    let content =
      withFilePrinter LogLevel.L2 (fun p ->
        p.PrintWarnLine "careful"
        p.PrintErrorLine "broken")
    let expected = "[*] Warning: careful" + nl + "[*] Error: broken" + nl
    Assert.AreEqual<string>(expected, content)

  (* L1 is documented as logging errors only, which until now made no
     difference on this channel because errors were all it carried. *)
  [<TestMethod>]
  member _.``Warnings are suppressed when the log level is quiet``() =
    let content =
      withFilePrinter LogLevel.L1 (fun p ->
        p.PrintWarnLine "careful"
        p.PrintWarn "also careful"
        p.PrintErrorLine "broken")
    Assert.AreEqual<string>("[*] Error: broken" + nl, content)

  [<TestMethod>]
  member _.``PrintWarn does not append a trailing newline``() =
    let content =
      withFilePrinter LogLevel.L2 (fun p ->
        p.PrintWarn "a"
        p.PrintWarn "b")
    Assert.AreEqual<string>("[*] Warning: a[*] Warning: b", content)

  (* Warnings share the error channel, so they must not land in the stdout
     cache where a stdout redirect would swallow them. *)
  [<TestMethod>]
  member _.``ConsoleCachedPrinter routes warnings to stderr``() =
    let out, err =
      withCachedPrinter (fun p _ ->
        p.PrintLine("normal", LogLevel.L2)
        p.PrintWarnLine "careful")
    Assert.AreEqual<string>("normal" + nl, out)
    Assert.AreEqual<string>("[*] Warning: careful" + nl, err)

  (* A tool that prints a great deal hands the printer its standard output
     stream, and the cache then reaches the stream as the very bytes the
     console's encoding gives the text, whether or not the text is all ASCII
     and whatever that encoding makes of a character it cannot write. *)
  [<TestMethod>]
  member _.``ConsoleCachedPrinter writes a given stream the console bytes``() =
    let text = "plain" + nl + "caf\u00e9" + nl
    use stream = new MemoryStream()
    let printer = new ConsoleCachedPrinter(LogLevel.L2, stream) :> IPrinter
    printer.PrintLine("plain", LogLevel.L2)
    printer.PrintLine("caf\u00e9", LogLevel.L2)
    printer.Flush()
    let expected = Console.OutputEncoding.GetBytes text
    CollectionAssert.AreEqual(expected, stream.ToArray())

  (* All-ASCII text, which is nearly all of it, takes a faster path; the bytes
     have to come out the same. *)
  [<TestMethod>]
  member _.``ConsoleCachedPrinter writes ASCII text as the same bytes``() =
    use stream = new MemoryStream()
    let printer = new ConsoleCachedPrinter(LogLevel.L2, stream) :> IPrinter
    printer.PrintRow [| "00401000:"; "push rbp" |]
    printer.Flush()
    let text = Console.OutputEncoding.GetString(stream.ToArray())
    let expected = String(' ', 15) + "00401000:" + " push rbp" + nl
    Assert.AreEqual<string>(expected, text)
