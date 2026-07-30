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

namespace B2R2.Tests

open System
open B2R2
open Microsoft.VisualStudio.TestTools.UnitTesting

[<TestClass>]
type ErrorCaseTests() =
  (* toMessage ends in a wildcard that raises, so a case added without a message
     describes itself by throwing. Nothing else in the build catches that, which
     is what let the enum drift away from the exceptions it mirrors. *)
  [<TestMethod>]
  member _.``[ErrorCase] every case has a message test``() =
    for case in Enum.GetValues<ErrorCase>() do
      let msg = ErrorCase.toMessage case
      Assert.AreEqual<bool>(false, String.IsNullOrWhiteSpace msg)

  (* The values are contiguous from zero, so that deleting a case renumbers the
     rest instead of leaving a dead integer inside the range. *)
  [<TestMethod>]
  member _.``[ErrorCase] the values are contiguous test``() =
    let values = Enum.GetValues<ErrorCase>() |> Array.map int |> Array.sort
    let expected = [| 0 .. values.Length - 1 |]
    Assert.AreEqual<string>(String.Join(",", expected),
                            String.Join(",", values))

  (* A value outside the enumeration is a caller error rather than a message to
     render, so it must not fall through to an empty string. Contiguity is what
     makes the case count the first value that is not a case. *)
  [<TestMethod>]
  member _.``[ErrorCase] an undeclared case is rejected test``() =
    let count = Enum.GetValues<ErrorCase>().Length
    for value in [ count; count + 1; 0xbad ] do
      let undeclared = enum<ErrorCase> value
      Assert.ThrowsExactly<ArgumentException>(fun () ->
        ErrorCase.toMessage undeclared |> ignore) |> ignore
