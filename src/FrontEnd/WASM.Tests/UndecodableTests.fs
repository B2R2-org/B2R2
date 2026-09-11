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

namespace B2R2.FrontEnd.WASM.Tests

open System
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.WASM
open Microsoft.VisualStudio.TestTools.UnitTesting

/// Pins that a byte the spec assigns to nothing is reported as a parsing
/// failure rather than decoded into some neighbouring opcode. WASM leaves
/// holes in every one of its four opcode spaces, and a decoder that fills one
/// in reads the bytes after it as operands of an instruction that is not
/// there, which walks the rest of the function body off its boundaries.
[<TestClass>]
type UndecodableTests() =
  static let parser =
    WASMParser(BinReader.Init Endian.Little) :> IInstructionParsable

  [<TestMethod>]
  member _.``[WASM] Unassigned Opcode Does Not Parse Test``() =
    for hex in [| "0a"; "27"; "c5"; "fc12"; "fe04" |] do
      let bytes = ByteArray.ofHexString hex
      Assert.ThrowsExactly<ParsingFailureException>(fun () ->
        parser.Parse(ReadOnlySpan bytes, 0UL) |> ignore) |> ignore
