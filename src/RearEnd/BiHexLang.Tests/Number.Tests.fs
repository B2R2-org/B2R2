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

namespace B2R2.RearEnd.BiHexLang.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2.RearEnd.BiHexLang

[<TestClass>]
type NumberTests() =
  let parser = Parser()

  let testNum fmt bs result =
    let expected = Number(fmt, bs)
    match result with
    | Ok(e: Expr) ->
      Assert.AreEqual<Expr>(expected, e)
    | Error e ->
      System.Console.WriteLine $"{e}"
      Assert.Fail("Parsing failed.")

  let testToString (expected: string) str =
    match parser.Run str with
    | Ok e -> Assert.AreEqual<string>(expected, Expr.ToString e)
    | _ -> Assert.Fail("Parsing failed.")

  [<TestMethod>]
  member _.``Hex number parsing tests``() =
    testNum Hex [| 0x00uy; 0x00uy; 0x00uy; 0x00uy |] <| parser.Run "0x00000000"
    testNum Hex [| 0x23uy; 0x01uy |] <| parser.Run "123"
    testNum Hex [| 0x34uy; 0x12uy |] <| parser.Run "0x1234"
    testNum Hex [| 0x01uy |] <| parser.Run "1"
    testNum Hex [| 0x42uy |] <| parser.Run "42"
    testNum Hex [| 0x42uy |] <| parser.Run "0x42"
    testNum Hex [| 0x4uy; 0x3uy; 0x2uy; 0x1uy |] <| parser.Run "1020304"
    testNum Hex [| 0x4uy; 0x3uy; 0x2uy; 0x1uy |] <| parser.Run "0x1020304"

  [<TestMethod>]
  member _.``Binary number parsing tests``() =
    testNum Bin [| 0x5uy |] <| parser.Run "0b0101"
    testNum Bin [| 0x5fuy |] <| parser.Run "0b01011111"
    testNum Bin [| 0x44uy; 0x43uy; 0x42uy; 0x41uy |]
    <| parser.Run "0b01000001010000100100001101000100"

  [<TestMethod>]
  member _.``Octal number parsing tests``() =
    testNum Oct [| 0x1uy |] <| parser.Run "0o1"
    testNum Oct [| 0xauy |] <| parser.Run "0o12"
    testNum Oct [| 0x42uy |] <| parser.Run "0o102"
    testNum Oct [| 0x6duy; 0x0buy |] <| parser.Run "0o5555"
    testNum Oct [| 0x6duy; 0x5buy |] <| parser.Run "0o55555"
    testNum Oct [| 0x6duy; 0xdbuy; 0x02uy |] <| parser.Run "0o555555"
    testNum Oct [| 0x6duy; 0xdbuy; 0x16uy |] <| parser.Run "0o5555555"
    testNum Oct [| 0x6duy; 0xdbuy; 0xb6uy |] <| parser.Run "0o55555555"
    testNum Oct [| 0x6duy; 0xdbuy; 0xb6uy; 0x05uy |] <| parser.Run "0o555555555"

  [<TestMethod>]
  member _.``Decimal number parsing tests``() =
    testNum Dec [| 0x0uy |] <| parser.Run "0d0"
    testNum Dec [| 0x42uy |] <| parser.Run "0d66"
    testNum Dec [| 0x78uy; 0x56uy; 0x34uy; 0x12uy |] <| parser.Run "0d305419896"

  [<TestMethod>]
  member _.``Number ToString tests``() =
    testToString "0x1234" "0x1234"
    testToString "0x1234" "1234"
    testToString "0x00" "0x0"
    testToString "0x01" "0x1"
    testToString "0x12345678901234567890" "0x12345678901234567890"
    testToString "0b0" "0b0"
    testToString "0b1" "0b01"
    testToString "0b101011010111101" "0b101011010111101"
    testToString "0o0" "0o0"
    testToString "0o4" "0o4"
    testToString "0o123" "0o123"
    testToString "0o12345" "0o12345"
    testToString "0o1234512345" "0o1234512345"
    testToString "0o123451234512345" "0o0000123451234512345"
    testToString "0d0" "0d0"
    testToString "0d42" "0d42"
    testToString "0d175281381175281381" "0d175281381175281381"
