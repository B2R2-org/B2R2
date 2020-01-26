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
  member __.``decodeUInt64 Test`` () =
    let u64 = [|
      ([| 0x00uy; |], 0x00UL)
      ([| 0x7fuy; |], 0x7fUL)
      ([| 0x80uy; 0x01uy; |], 0x80UL)
      ([| 0xffuy; 0x01uy; |], 0xffUL)
      ([| 0x9duy; 0x12uy; |], 0x091dUL)
      ([| 0x97uy; 0xdeuy; 0x03uy; |], 0xef17UL)
      ([| 0xe5uy; 0x8euy; 0x26uy; |], 0x098765UL)
      ([| 0xffuy; 0xffuy; 0x03uy; |], 0xffffUL)
      ([| 0xffuy; 0xffuy; 0xffuy; 0xffuy; 0xffuy;
          0xffuy; 0xffuy; 0xffuy; 0xffuy; 0x01uy; |], 18446744073709551615UL)
      ([| 0x83uy; 0x00uy; |], 0x03UL)
    |]
    for arr, res in u64 do
      let r = BinReader.Init (arr, Endian.Little)
      let v, c = r.PeekUInt64LEB128 0
      Assert.AreEqual(res, v)

  [<TestMethod>]
  member __.``decodeUInt32 Test`` () =
    let u32 = [|
      ([| 0x00uy; |], 0x00u)
      ([| 0x7fuy; |], 0x7fu)
      ([| 0x80uy; 0x01uy; |], 0x80u)
      ([| 0xffuy; 0x01uy; |], 0xffu)
      ([| 0x9duy; 0x12uy; |], 0x091du)
      ([| 0x97uy; 0xdeuy; 0x03uy; |], 0xef17u)
      ([| 0xe5uy; 0x8euy; 0x26uy; |], 0x098765u)
      ([| 0xffuy; 0xffuy; 0x03uy; |], 0xffffu)
      ([| 0x83uy; 0x00uy; |], 0x03u)
    |]
    for arr, res in u32 do
      let r = BinReader.Init (arr, Endian.Little)
      let v, c = r.PeekUInt32LEB128 0
      Assert.AreEqual(res, v)

  [<TestMethod>]
  member __.``decodeSInt64 Test`` () =
    let s64 = [|
      ([| 0xffuy; 0xffuy; 0xffuy; 0xffuy; 0xffuy;
          0xffuy; 0xffuy; 0xffuy; 0xffuy; 0x00uy; |], 9223372036854775807L)
      ([| 0x97uy; 0xdeuy; 0x03uy; |], 0xef17L)
      ([| 0xC0uy; 0x00uy; |], 0x40L)
      ([| 0x3fuy; |], 0x3fL)
      ([| 0x01uy; |], 1L)
      ([| 0x00uy; |], 0L)
      ([| 0x7fuy; |], -1L)
      ([| 0x40uy; |], -64L)
      ([| 0xbfuy; 0x7fuy; |], -65L)
      ([| 0x9Buy; 0xF1uy; 0x59uy; |], -624485L)
      ([| 0x80uy; 0x80uy; 0x80uy; 0x80uy; 0x80uy;
          0x80uy; 0x80uy; 0x80uy; 0x80uy; 0x7fuy; |], -9223372036854775808L)
      ([| 0x80uy; 0x80uy; 0x80uy; 0x80uy; 0x7fuy; |], -268435456L)
    |]
    for arr, res in s64 do
      let r = BinReader.Init (arr, Endian.Little)
      let v, c = r.PeekInt64LEB128 0
      Assert.AreEqual(res, v)

  [<TestMethod>]
  member __.``decodeSInt32 Test`` () =
    let s32 = [|
      ([| 0x97uy; 0xdeuy; 0x03uy; |], 0xef17)
      ([| 0xC0uy; 0x00uy; |], 0x40)
      ([| 0x3fuy; |], 0x3f)
      ([| 0x01uy; |], 1)
      ([| 0x00uy; |], 0)
      ([| 0x7fuy; |], -1)
      ([| 0x40uy; |], -64)
      ([| 0xbfuy; 0x7fuy; |], -65)
      ([| 0x9Buy; 0xF1uy; 0x59uy; |], -624485)
      ([| 0x80uy; 0x80uy; 0x80uy; 0x80uy; 0x7fuy; |], -268435456)
    |]
    for arr, res in s32 do
        let r = BinReader.Init (arr, Endian.Little)
        let v, c = r.PeekInt32LEB128 0
        Assert.AreEqual(res, v)

  [<TestMethod>]
  member __.``Overflow handling Test`` () =
    let overflow = [|
      //FIXME
      //[| 0xffuy; |]
      //[| 0x80uy; 0x80uy; |]
      [| 0xffuy; 0x80uy; 0x80uy; 0x80uy; 0x80uy;
         0x80uy; 0x80uy; 0x80uy; 0x80uy; 0x80uy; 0x7fuy; |]
    |]
    let initBR bytes = BinReader.Init bytes
    let decodeOverflowed func =
      try
        func 0 |> ignore
        false
      with
        | :? LEB128.LEB128DecodeException -> true
        | _ -> false

    let u64Result = Array.map (fun arr -> initBR(arr).PeekUInt64LEB128 |> decodeOverflowed) overflow
    Assert.IsTrue (Array.forall (fun ov -> ov) u64Result)
    let u32Result = Array.map (fun arr -> initBR(arr).PeekUInt32LEB128 |> decodeOverflowed) overflow
    Assert.IsTrue (Array.forall (fun ov -> ov) u32Result)
    let s64Result = Array.map (fun arr -> initBR(arr).PeekInt64LEB128 |> decodeOverflowed) overflow
    Assert.IsTrue (Array.forall (fun ov -> ov) s64Result)
    let s32Result = Array.map (fun arr -> initBR(arr).PeekInt32LEB128 |> decodeOverflowed) overflow
    Assert.IsTrue (Array.forall (fun ov -> ov) s32Result)