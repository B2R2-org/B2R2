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
type ASTTests() =
  let parser = Parser()

  let (<=>) str (expected: string) =
    match parser.Run str with
    | Ok e ->
      Assert.AreEqual<string>(expected, Expr.ToString e)
    | Error e ->
      System.Console.WriteLine $"{e}"
      Assert.Fail "Parsing failed."

  [<TestMethod>]
  member _.``Arithmetic op tests``() =
    "1 + 2 - 3" <=> "1 + 2 - 3"
    "0x1 + 0x2 * 0x3 / 0x4" <=> "0x01 + 0x02 * 0x03 / 0x04"
    "(0x1 + 0x2) * (0x3 - 0x4)" <=> "(0x01 + 0x02) * (0x03 - 0x04)"
    "0x1 + 0x2 * (0x3 / 0x4)" <=> "0x01 + 0x02 * (0x03 / 0x04)"
    "0x1 % 0x2 + 0x3" <=> "0x01 % 0x02 + 0x03"
    "0x1 | (0x2 << 0x1)" <=> "0x01 | (0x02 << 0x01)"
    "(0x1 & 0x2) ^ 0x3" <=> "(0x01 & 0x02) ^ 0x03"
    "~0x4242 + 0x1" <=> "~0x4242 + 0x01"
    "-0x1 * 0x42 - 0x42" <=> "-0x01 * 0x42 - 0x42"

  [<TestMethod>]
  member _.``Casting op tests``() =
    "dec(0x42 + 1)" <=> "dec(0x42 + 1)"
    "dec(0x42 + hex(1))" <=> "dec(0x42 + hex(1))"
    "oct(0x42 * 2 + 0x42)" <=> "oct(0x42 * 2 + 0x42)"
    "hex(oct(0x42) + 1)" <=> "hex(oct(0x42) + 1)"
