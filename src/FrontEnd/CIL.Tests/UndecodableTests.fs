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

namespace B2R2.FrontEnd.CIL.Tests

open System
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.CIL
open Microsoft.VisualStudio.TestTools.UnitTesting

/// Pins that a byte ECMA-335 assigns to nothing is reported as a parsing
/// failure rather than decoded into some neighbouring opcode, and that an
/// instruction the span cannot hold whole is reported the same way. A decoder
/// that fills a hole in reads the bytes after it as an operand that is not
/// there, which walks the rest of the method body off its boundaries.
[<TestClass>]
type UndecodableTests() =
  static let parser =
    CILParser(BinReader.Init Endian.Little) :> IInstructionParsable

  static let assertFails hex =
    let bytes = ByteArray.ofHexString hex
    Assert.ThrowsExactly<ParsingFailureException>(fun () ->
      parser.Parse(ReadOnlySpan bytes, 0UL) |> ignore) |> ignore

  /// One byte from each end of every run the one-byte space leaves
  /// unassigned.
  static let unassigned =
    [| "24"
       "77"
       "78"
       "a6"
       "b2"
       "bb"
       "c1"
       "c4"
       "c5"
       "c7"
       "cf"
       "e1"
       "fd"
       "ff" |]

  /// Instructions cut short inside the operand each takes.
  static let truncated =
    [| ""
       "0e"
       "20000000"
       "21"
       "2b"
       "3800"
       "28010000"
       "fe"
       "fe09"
       "fe0900"
       "fe12"
       "fe16010000" |]

  [<TestMethod>]
  member _.``[CIL] Unassigned Opcode Does Not Parse Test``() =
    for hex in unassigned do
      assertFails (hex + "00000000")

  [<TestMethod>]
  member _.``[CIL] Unassigned Two Byte Opcode Does Not Parse Test``() =
    for hex in [| "fe08"; "fe10"; "fe1b"; "fe1f"; "feff" |] do
      assertFails (hex + "00000000")

  (* The operand an instruction takes has to be there whole; a span that ends
     inside it is a failure of the input rather than a shorter instruction. *)
  [<TestMethod>]
  member _.``[CIL] Truncated Instruction Does Not Parse Test``() =
    for hex in truncated do
      assertFails hex

  (* A switch says how long it is, and one that says more than the span holds
     is refused rather than read past the end. *)
  [<TestMethod>]
  member _.``[CIL] Switch Longer Than Its Span Does Not Parse Test``() =
    assertFails "4501000000"
    assertFails "450200000000000000"
    assertFails "45ffffffff00000000"

// vim: set tw=80 sts=2 sw=2:
