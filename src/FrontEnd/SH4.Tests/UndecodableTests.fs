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

namespace B2R2.FrontEnd.SH4.Tests

open System
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.SH4
open Microsoft.VisualStudio.TestTools.UnitTesting

/// Pins that undecodable bytes are reported as a parsing failure rather than
/// parsed into a sentinel opcode, whose failure used to surface only when the
/// instruction was lifted, so a linear sweep saw every address as code.
[<TestClass>]
type UndecodableTests() =
  static let reader = BinReader.Init Endian.Little

  static let parser = SH4Parser(reader) :> IInstructionParsable

  [<TestMethod>]
  member _.``[SH4] Undecodable Bytes Do Not Parse Test``() =
    for hex in [| "b44c"; "8046"; "3100" |] do
      let bytes = ByteArray.ofHexString hex
      Assert.ThrowsExactly<ParsingFailureException>(fun () ->
        parser.Parse(ReadOnlySpan bytes, 0UL) |> ignore) |> ignore

  /// <summary>
  /// Pins the words that a field read too loosely used to let through.
  ///
  /// Each of these carries something in bits the instruction below it spells
  /// out: the field that names a register where the no-operand instructions
  /// have none, the bit saying a banked register is named where none is, and
  /// the bits below the ones naming a vector or a pair. Reading only the bits
  /// that name something made every one of these an instruction it is not.
  /// </summary>
  [<TestMethod>]
  member _.``[SH4] Words With Nonzero Reserved Fields Do Not Parse Test``() =
    for hex in [| "080f" (* 0f08: clrt with a register field *)
                  "090f" (* 0f09: nop with a register field *)
                  "0b0f" (* 0f0b: rts with a register field *)
                  "5340" (* 4053: stc.l naming no bank *)
                  "5740" (* 4057: ldc.l naming no bank *)
                  "fdf0" (* f0fd: ftrv over a word that is not one *)
                  "adf1" (* f1ad: fcnvsd naming an odd register *)
                  "bdf1" (* f1bd: fcnvds naming an odd register *) |] do
      let bytes = ByteArray.ofHexString hex
      Assert.ThrowsExactly<ParsingFailureException>(fun () ->
        parser.Parse(ReadOnlySpan bytes, 0UL) |> ignore) |> ignore
