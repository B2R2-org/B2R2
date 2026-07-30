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

namespace B2R2.FrontEnd.AVR.Tests

open System
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.AVR
open Microsoft.VisualStudio.TestTools.UnitTesting

/// Pins that undecodable bytes are reported as a parsing failure rather than
/// parsed into a sentinel opcode, whose failure used to surface only when the
/// instruction was lifted, so a linear sweep saw every address as code.
[<TestClass>]
type UndecodableTests() =
  static let reader = BinReader.Init Endian.Little

  static let parser = AVRParser(reader) :> IInstructionParsable

  [<TestMethod>]
  member _.``[AVR] Undecodable Bytes Do Not Parse Test``() =
    for hex in [| "1afc"; "5391"; "dcf8" |] do
      let bytes = ByteArray.ofHexString hex
      Assert.ThrowsExactly<ParsingFailureException>(fun () ->
        parser.Parse(ReadOnlySpan bytes, 0UL) |> ignore) |> ignore
