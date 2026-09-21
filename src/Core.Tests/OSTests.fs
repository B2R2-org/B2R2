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

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2

[<TestClass>]
type OSTests() =

  [<TestMethod>]
  member _.``OS ofString Test``() =
    Assert.AreEqual<OS>(OS.Windows, OS.ofString "WIN")
    Assert.AreEqual<OS>(OS.Linux, OS.ofString "linux")
    Assert.AreEqual<OS>(OS.MacOSX, OS.ofString "osx")
    Assert.AreEqual<OS>(OS.BareMetal, OS.ofString "bare-metal")
    Assert.AreEqual<OS>(OS.BareMetal, OS.ofString "Firmware")
    Assert.AreEqual<OS>(OS.UnknownOS, OS.ofString "unknown")
    Assert.ThrowsExactly<UnknownOSException>(fun () ->
      OS.ofString "plan9" |> ignore)
    |> ignore

  (* Every value has to have a string, or naming one that does not raises where
     a caller is only rendering what a file told it. *)
  [<TestMethod>]
  member _.``OS toString Test``() =
    Assert.AreEqual<string>("Windows", OS.toString OS.Windows)
    Assert.AreEqual<string>("Linux", OS.toString OS.Linux)
    Assert.AreEqual<string>("Mac", OS.toString OS.MacOSX)
    Assert.AreEqual<string>("BareMetal", OS.toString OS.BareMetal)
    Assert.AreEqual<string>("UnknownOS", OS.toString OS.UnknownOS)
