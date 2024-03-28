(*
  B2R2 - the Next-Generation Reversing Platform

  Copyright (c) SoftSec Lab. @ KAIST, since 2016

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
*)

namespace B2R2.Core.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2

[<TestClass>]
type BinReaderTests () =

  [<TestMethod>]
  member __.``Little-endian vs. Big-endian Test`` () =
    let sample = [| 0x11uy; 0x22uy; 0x33uy; 0x44uy |]
    let lr = BinReader.Init Endian.Little
    let v = lr.ReadInt32 (System.ReadOnlySpan sample, 0)
    Assert.AreEqual (expected=0x44332211, actual=v)
    let br = BinReader.Init Endian.Big
    let v = br.ReadInt32 (System.ReadOnlySpan sample, 0)
    Assert.AreEqual (expected=0x11223344, actual=v)

  [<TestMethod>]
  member __.``Read Overflow Test`` () =
    let sample = [| 0x11uy; 0x22uy |]
    let r = BinReader.Init Endian.Little
    let v =
      try r.ReadInt32 (System.ReadOnlySpan sample, 0)
      with :? System.ArgumentOutOfRangeException -> 0
    Assert.AreEqual (expected=0, actual=v)

  [<TestMethod>]
  member __.``LEB128 to UInt64 Test`` () =
    let samples =
      [| (* (LEB encoded bytes, Decoded number) *)
        ([| 0x00uy |], 0x00UL)
        ([| 0x7fuy |], 0x7fUL)
        ([| 0x80uy; 0x01uy |], 0x80UL)
        ([| 0xffuy; 0x01uy |], 0xffUL)
        ([| 0x9duy; 0x12uy |], 0x091dUL)
        ([| 0x97uy; 0xdeuy; 0x03uy |], 0xef17UL)
        ([| 0xe5uy; 0x8euy; 0x26uy |], 0x098765UL)
        ([| 0xffuy; 0xffuy; 0x03uy |], 0xffffUL)
        ([| 0xffuy; 0xffuy; 0xffuy; 0xffuy; 0xffuy;
            0xffuy; 0xffuy; 0xffuy; 0xffuy; 0x01uy |], 18446744073709551615UL)
        ([| 0x83uy; 0x00uy |], 0x03UL)
      |]
    for bytes, value in samples do
      let r = BinReader.Init ()
      let v, _ = r.ReadUInt64LEB128 (bytes, 0)
      Assert.AreEqual (expected=value, actual=v)

  [<TestMethod>]
  member __.``LEB128 to UInt32 Test`` () =
    let samples =
      [| (* (LEB encoded bytes, Decoded number) *)
        ([| 0x00uy |], 0x00u)
        ([| 0x7fuy |], 0x7fu)
        ([| 0x80uy; 0x01uy |], 0x80u)
        ([| 0xffuy; 0x01uy |], 0xffu)
        ([| 0x9duy; 0x12uy |], 0x091du)
        ([| 0x97uy; 0xdeuy; 0x03uy |], 0xef17u)
        ([| 0xe5uy; 0x8euy; 0x26uy |], 0x098765u)
        ([| 0xffuy; 0xffuy; 0x03uy |], 0xffffu)
        ([| 0x83uy; 0x00uy |], 0x03u)
      |]
    for bytes, value in samples do
      let r = BinReader.Init ()
      let v, _ = r.ReadUInt32LEB128 (bytes, 0)
      Assert.AreEqual (expected=value, actual=v)

  [<TestMethod>]
  member __.``LEB128 to SInt64 Test`` () =
    let samples =
      [| (* (LEB encoded bytes, Decoded number) *)
        ([| 0xffuy; 0xffuy; 0xffuy; 0xffuy; 0xffuy;
            0xffuy; 0xffuy; 0xffuy; 0xffuy; 0x00uy; |], 9223372036854775807L)
        ([| 0x97uy; 0xdeuy; 0x03uy |], 0xef17L)
        ([| 0xC0uy; 0x00uy |], 0x40L)
        ([| 0x3fuy |], 0x3fL)
        ([| 0x01uy |], 1L)
        ([| 0x00uy |], 0L)
        ([| 0x7fuy |], -1L)
        ([| 0x40uy |], -64L)
        ([| 0xbfuy; 0x7fuy |], -65L)
        ([| 0x9Buy; 0xF1uy; 0x59uy |], -624485L)
        ([| 0x80uy; 0x80uy; 0x80uy; 0x80uy; 0x80uy;
            0x80uy; 0x80uy; 0x80uy; 0x80uy; 0x7fuy; |], -9223372036854775808L)
        ([| 0x80uy; 0x80uy; 0x80uy; 0x80uy; 0x7fuy |], -268435456L)
      |]
    for bytes, value in samples do
      let r = BinReader.Init ()
      let v, _ = r.ReadInt64LEB128 (bytes, 0)
      Assert.AreEqual (expected=value, actual=v)

  [<TestMethod>]
  member __.``LEB128 to SInt32 Test`` () =
    let samples =
      [| (* (LEB encoded bytes, Decoded number) *)
        ([| 0x97uy; 0xdeuy; 0x03uy |], 0xef17)
        ([| 0xC0uy; 0x00uy |], 0x40)
        ([| 0x3fuy |], 0x3f)
        ([| 0x01uy |], 1)
        ([| 0x00uy |], 0)
        ([| 0x7fuy |], -1)
        ([| 0x40uy |], -64)
        ([| 0xbfuy; 0x7fuy |], -65)
        ([| 0x9Buy; 0xF1uy; 0x59uy |], -624485)
        ([| 0x80uy; 0x80uy; 0x80uy; 0x80uy; 0x7fuy |], -268435456)
      |]
    for bytes, value in samples do
      let r = BinReader.Init ()
      let v, _ = r.ReadInt32LEB128 (bytes, 0)
      Assert.AreEqual (expected=value, actual=v)

  [<TestMethod>]
  member __.``LEB128 Overflow Handling Test`` () =
    let testcase =
      [| 0xffuy; 0x80uy; 0x80uy; 0x80uy; 0x80uy;
         0x80uy; 0x80uy; 0x80uy; 0x80uy; 0x80uy; 0x7fuy |]
    let toBool decode =
      try
        decode () |> ignore
        false
      with
        | :? LEB128DecodeException -> true
        | _ -> false
    let r = BinReader.Init ()
    toBool (fun () -> r.ReadUInt64LEB128 (testcase, 0)) |> Assert.IsTrue
    toBool (fun () -> r.ReadUInt32LEB128 (testcase, 0)) |> Assert.IsTrue
    toBool (fun () -> r.ReadInt64LEB128 (testcase, 0)) |> Assert.IsTrue
    toBool (fun () -> r.ReadInt32LEB128 (testcase, 0)) |> Assert.IsTrue