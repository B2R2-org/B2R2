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

namespace B2R2.FrontEnd.BinFile.Tests

open System
open B2R2
open B2R2.FrontEnd.BinFile
open Microsoft.VisualStudio.TestTools.UnitTesting

/// Tests for the string readers shared by the binary file parsers, which
/// differ in what they do when a terminator is missing.
[<TestClass>]
type FileHelperTests() =
  (* "hi\0bye\0" *)
  static let twoStrings =
    [| 0x68uy; 0x69uy; 0x00uy; 0x62uy; 0x79uy; 0x65uy; 0x00uy |]

  static let readWithNextOffset (bytes: byte[]) offset =
    FileHelper.readCStringWithNextOffset (ReadOnlySpan bytes) offset

  [<TestMethod>]
  member _.``[FileHelper] consecutive strings are read in turn``() =
    let struct (first, next) = readWithNextOffset twoStrings 0
    let struct (second, last) = readWithNextOffset twoStrings next
    Assert.AreEqual<string>("hi", first)
    Assert.AreEqual<int>(3, next)
    Assert.AreEqual<string>("bye", second)
    Assert.AreEqual<int>(7, last)

  [<TestMethod>]
  member _.``[FileHelper] empty string consumes its terminator``() =
    let bytes = [| 0x00uy; 0x61uy; 0x00uy |]
    let struct (str, next) = readWithNextOffset bytes 0
    Assert.AreEqual<string>("", str)
    Assert.AreEqual<int>(1, next)

  [<TestMethod>]
  member _.``[FileHelper] terminator may be the last byte``() =
    let bytes = [| 0x6fuy; 0x6buy; 0x00uy |]
    let struct (str, next) = readWithNextOffset bytes 2
    Assert.AreEqual<string>("", str)
    Assert.AreEqual<int>(3, next)
    Assert.AreEqual<string>("ok", FileHelper.readCString (ReadOnlySpan bytes) 0)

  [<TestMethod>]
  member _.``[FileHelper] a missing terminator is an error``() =
    (* The permissive reader takes the whole region instead. *)
    let bytes = [| 0x6fuy; 0x6buy |]
    Assert.ThrowsExactly<IndexOutOfRangeException>(fun () ->
      readWithNextOffset bytes 0 |> ignore) |> ignore
    Assert.AreEqual<string>("ok", ByteArray.extractCString bytes 0)

  [<TestMethod>]
  member _.``[FileHelper] offsets outside the span are errors``() =
    Assert.ThrowsExactly<IndexOutOfRangeException>(fun () ->
      readWithNextOffset twoStrings 7 |> ignore) |> ignore
    Assert.ThrowsExactly<IndexOutOfRangeException>(fun () ->
      readWithNextOffset twoStrings 8 |> ignore) |> ignore
    Assert.ThrowsExactly<IndexOutOfRangeException>(fun () ->
      readWithNextOffset twoStrings -1 |> ignore) |> ignore

  [<TestMethod>]
  member _.``[FileHelper] a full fixed-width field is read whole``() =
    (* A Mach-O name field that fills all 16 bytes carries no terminator, so
       the field boundary is the only thing that stops the read. *)
    let name = "__TEXT_16_CHARS!"
    let bytes = Array.append (Text.Encoding.ASCII.GetBytes name) "ab\000"B
    let span = ReadOnlySpan bytes
    Assert.AreEqual<string>(name, FileHelper.readCStringOfSize span 0 16)
    Assert.AreEqual<string>("ab", FileHelper.readCStringOfSize span 16 3)
