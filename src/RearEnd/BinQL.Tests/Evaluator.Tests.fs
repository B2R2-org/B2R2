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

namespace B2R2.RearEnd.BinQL.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2.RearEnd.BinQL

[<TestClass>]
type EvaluatorTests() =
  let parser = Parser()
  let evaluator = Evaluator()

  let (==>) str (expected: string) =
    match parser.Run str with
    | Ok e ->
      Assert.AreEqual<string>(expected, evaluator.EvalExprToString e)
    | _ ->
      Assert.Fail "Parsing failed."

  [<TestMethod>]
  member _.``Arithmetic evaluation tests``() =
    "1 + 2 - 3" ==> "0"
    "0x1 * 2 - 0x4" ==> "0xFE"
    "0d10 * 0d4 - 0d42" ==> "-2"
    "0x00000000" ==> "0x00000000"
    "(0x00004200 ^ 0x42420042 & 0x00FFFFFF)" ==> "0x00424242"
    "0xFFFFFFFF + 0x1" ==> "0x00000000"
    "0x00000000 - 0x1" ==> "0xFFFFFFFF"
    "0xFFFF + 0x0002" ==> "0x0001"
    "0x0000 - 0x0002" ==> "0xFFFE"

  [<TestMethod>]
  member _.``Arithmetic evaluation tests 2``() =
    "0x10000000 + 0xFF" ==> "0x100000FF"
    "0xFF0000FF - 0xFF" ==> "0xFF000000"
    "0x00000002 * 0xFF" ==> "0x000001FE"
    "0x00000008 / 0xFF" ==> "0x00000000"
    "0x00000008 % 0xFF" ==> "0x00000008"
    "0x10000008 & 0xFF" ==> "0x00000008"
    "0x10000008 | 0xFF" ==> "0x100000FF"
    "0x10000008 ^ 0xFF" ==> "0x100000F7"
    "0xF0000008 << 0x4" ==> "0x00000080"
    "0xFF << 0x4" ==> "0xF0"
    "0xFF << 0x8" ==> "0x00"
    "0xFF >> 0x4" ==> "0x0F"
    "0xFF >> 0x8" ==> "0x00"
    "hex(oct(0x42) + 1)" ==> "0x43"

  [<TestMethod>]
  member _.``String tests``() =
    "\"\"" ==> "0x00"
    "\"ABCD\"" ==> "0x41424344"
    "dec(\"a\")" ==> "97"
    "\"AA\" * 4" ==> "0x4141414141414141"
    "0d10 * \"AB\"" ==> "0x4142414241424142414241424142414241424142"

  [<TestMethod>]
  member _.``Concatenation tests``() =
    "(0x00004200 ^ 0x42420042 & 0x00FFFFFF) . 0xFFFF" ==> "0x00424242FFFF"
    "0xFF0000 . (0xFFFF0000 | 0xFF) . 0x4242" ==> "0xFF0000FFFF00FF4242"
    "0x82 . 0x8242 . 0x82424242" ==> "0x82824282424242"
    "\"AAAAAAAA\" . 0x42424242" ==> "0x414141414141414142424242"
    "(0x4 * 0x2) . 0x4242" ==> "0x084242"
