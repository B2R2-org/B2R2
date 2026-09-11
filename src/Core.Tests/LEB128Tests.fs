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

module B2R2.Core.Tests.LEB128

open System
open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2

[<TestClass>]
type LEB128Tests() =

  [<TestMethod>]
  member _.``decodeUInt64 Test``() =
    let u64 =
      [| ([| 0x00uy |], 0x00UL)
         ([| 0x7fuy |], 0x7fUL)
         ([| 0x80uy; 0x01uy |], 0x80UL)
         ([| 0xffuy; 0x01uy |], 0xffUL)
         ([| 0x9duy; 0x12uy |], 0x091dUL)
         ([| 0x97uy; 0xdeuy; 0x03uy |], 0xef17UL)
         ([| 0xe5uy; 0x8euy; 0x26uy |], 0x098765UL)
         ([| 0xffuy; 0xffuy; 0x03uy |], 0xffffUL)
         ([| 0xffuy
             0xffuy
             0xffuy
             0xffuy
             0xffuy
             0xffuy
             0xffuy
             0xffuy
             0xffuy
             0x01uy |], 18446744073709551615UL)
         ([| 0x83uy; 0x00uy |], 0x03UL) |]
    for arr, res in u64 do
      let v, _ = LEB128.decodeUInt64Bytes arr
      Assert.AreEqual<uint64>(res, v)

  [<TestMethod>]
  member _.``decodeUInt32 Test``() =
    let u32 =
      [| ([| 0x00uy |], 0x00u)
         ([| 0x7fuy |], 0x7fu)
         ([| 0x80uy; 0x01uy |], 0x80u)
         ([| 0xffuy; 0x01uy |], 0xffu)
         ([| 0x9duy; 0x12uy |], 0x091du)
         ([| 0x97uy; 0xdeuy; 0x03uy |], 0xef17u)
         ([| 0xe5uy; 0x8euy; 0x26uy |], 0x098765u)
         ([| 0xffuy; 0xffuy; 0x03uy |], 0xffffu)
         ([| 0x83uy; 0x00uy |], 0x03u) |]
    for arr, res in u32 do
      let v, _ = LEB128.decodeUInt32Bytes arr
      Assert.AreEqual<uint32>(res, v)

  [<TestMethod>]
  member _.``decodeSInt64 Test``() =
    let s64 =
      [| ([| 0xffuy
             0xffuy
             0xffuy
             0xffuy
             0xffuy
             0xffuy
             0xffuy
             0xffuy
             0xffuy
             0x00uy |], 9223372036854775807L)
         ([| 0x97uy; 0xdeuy; 0x03uy |], 0xef17L)
         ([| 0xC0uy; 0x00uy |], 0x40L)
         ([| 0x3fuy |], 0x3fL)
         ([| 0x01uy |], 1L)
         ([| 0x00uy |], 0L)
         ([| 0x7fuy |], -1L)
         ([| 0x40uy |], -64L)
         ([| 0xbfuy; 0x7fuy |], -65L)
         ([| 0x9Buy; 0xF1uy; 0x59uy |], -624485L)
         ([| 0x80uy
             0x80uy
             0x80uy
             0x80uy
             0x80uy
             0x80uy
             0x80uy
             0x80uy
             0x80uy
             0x7fuy |], -9223372036854775808L)
         ([| 0x80uy; 0x80uy; 0x80uy; 0x80uy; 0x7fuy |], -268435456L) |]
    for arr, res in s64 do
      let v, _ = LEB128.decodeSInt64Bytes arr
      Assert.AreEqual<int64>(res, v)

  [<TestMethod>]
  member _.``decodeSInt32 Test``() =
    let s32 =
      [| ([| 0x97uy; 0xdeuy; 0x03uy |], 0xef17)
         ([| 0xC0uy; 0x00uy |], 0x40)
         ([| 0x3fuy |], 0x3f)
         ([| 0x01uy |], 1)
         ([| 0x00uy |], 0)
         ([| 0x7fuy |], -1)
         ([| 0x40uy |], -64)
         ([| 0xbfuy; 0x7fuy |], -65)
         ([| 0x9Buy; 0xF1uy; 0x59uy |], -624485)
         ([| 0x80uy; 0x80uy; 0x80uy; 0x80uy; 0x7fuy |], -268435456) |]
    for arr, res in s32 do
      let v, _ = LEB128.decodeSInt32Bytes arr
      Assert.AreEqual<int>(res, v)

  [<TestMethod>]
  member _.``Overflow handling Test``() =
    let overflow =
      [| [| 0xffuy |]
         [| 0x80uy; 0x80uy |]
         [| 0xffuy
            0x80uy
            0x80uy
            0x80uy
            0x80uy
            0x80uy
            0x80uy
            0x80uy
            0x80uy
            0x80uy
            0x7fuy |] |]
    overflow
    |> Array.iter (fun bs ->
      Assert.Throws<LEB128.DecodeException>(fun () ->
        LEB128.decodeUInt64Bytes bs |> ignore)
      |> ignore)
    overflow
    |> Array.iter (fun bs ->
      Assert.Throws<LEB128.DecodeException>(fun () ->
        LEB128.decodeUInt32Bytes bs |> ignore)
      |> ignore)
    overflow
    |> Array.iter (fun bs ->
      Assert.Throws<LEB128.DecodeException>(fun () ->
        LEB128.decodeSInt64Bytes bs |> ignore)
      |> ignore)
    overflow
    |> Array.iter (fun bs ->
      Assert.Throws<LEB128.DecodeException>(fun () ->
        LEB128.decodeSInt32Bytes bs |> ignore)
      |> ignore)

  [<TestMethod>]
  member _.``encodeUInt64 Test``() =
    let u64 =
      [| (0x00UL, "00")
         (0x7fUL, "7F")
         (0x80UL, "8001")
         (0xffUL, "FF01")
         (0x091dUL, "9D12")
         (0xef17UL, "97DE03")
         (0x098765UL, "E58E26")
         (0xffffUL, "FFFF03")
         (18446744073709551615UL, "FFFFFFFFFFFFFFFFFF01") |]
    for v, res in u64 do
      Assert.AreEqual<string>(res, Convert.ToHexString(LEB128.encodeUInt64 v))

  [<TestMethod>]
  member _.``encodeUInt32 Test``() =
    let u32 =
      [| (0x00u, "00")
         (0x7fu, "7F")
         (0x80u, "8001")
         (0xffu, "FF01")
         (0x091du, "9D12")
         (0xef17u, "97DE03")
         (0x098765u, "E58E26")
         (0xffffu, "FFFF03")
         (UInt32.MaxValue, "FFFFFFFF0F") |]
    for v, res in u32 do
      Assert.AreEqual<string>(res, Convert.ToHexString(LEB128.encodeUInt32 v))

  [<TestMethod>]
  member _.``encodeSInt64 Test``() =
    let s64 =
      [| (0L, "00")
         (1L, "01")
         (-1L, "7F")
         (0x3fL, "3F")
         (0x40L, "C000")
         (-64L, "40")
         (-65L, "BF7F")
         (0xef17L, "97DE03")
         (-624485L, "9BF159")
         (-268435456L, "808080807F")
         (Int64.MaxValue, "FFFFFFFFFFFFFFFFFF00")
         (Int64.MinValue, "8080808080808080807F") |]
    for v, res in s64 do
      Assert.AreEqual<string>(res, Convert.ToHexString(LEB128.encodeSInt64 v))

  [<TestMethod>]
  member _.``encodeSInt32 Test``() =
    let s32 =
      [| (0, "00")
         (1, "01")
         (-1, "7F")
         (0x3f, "3F")
         (0x40, "C000")
         (-64, "40")
         (-65, "BF7F")
         (0xef17, "97DE03")
         (-624485, "9BF159")
         (-268435456, "808080807F")
         (Int32.MaxValue, "FFFFFFFF07")
         (Int32.MinValue, "8080808078") |]
    for v, res in s32 do
      Assert.AreEqual<string>(res, Convert.ToHexString(LEB128.encodeSInt32 v))

  [<TestMethod>]
  member _.``Round-trip Test``() =
    let unsigned =
      [ 0UL; 1UL; 0x7fUL; 0x80UL; 0xffffUL; 0x098765UL; UInt64.MaxValue ]
    for v in unsigned do
      let bs = LEB128.encodeUInt64 v
      let decoded, len = LEB128.decodeUInt64Bytes bs
      Assert.AreEqual<uint64>(v, decoded)
      Assert.AreEqual<int>(bs.Length, len)
    let signed =
      [ 0L; 1L; -1L; 64L; -64L; -65L; Int64.MaxValue; Int64.MinValue ]
    for v in signed do
      let bs = LEB128.encodeSInt64 v
      let decoded, len = LEB128.decodeSInt64Bytes bs
      Assert.AreEqual<int64>(v, decoded)
      Assert.AreEqual<int>(bs.Length, len)
