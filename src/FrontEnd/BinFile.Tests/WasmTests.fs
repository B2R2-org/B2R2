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

open B2R2
open B2R2.FrontEnd.BinFile
open Microsoft.VisualStudio.TestTools.UnitTesting
open type FileFormat

[<TestClass>]
type WasmTests () =
  static let parseFile fileName =
    let zipFile = fileName + ".zip"
    let fileNameInZip = fileName + ".wasm"
    let bytes = ZIPReader.readBytes WasmBinary zipFile fileNameInZip
    WasmBinFile ("", bytes) :> IBinFile

  static let file = parseFile "wasm_basic"

  [<TestMethod>]
  member __.``[Wasm] EntryPoint test`` () =
    Assert.AreEqual (Some 0x15AUL, file.EntryPoint)

  [<TestMethod>]
  member __.``[Wasm] file type test`` () =
    Assert.AreEqual (FileType.ExecutableFile, file.Type)

  [<TestMethod>]
  member __.``[Wasm] IsStripped test`` () =
    Assert.IsFalse (file.IsStripped)

  [<TestMethod>]
  member __.``[Wasm] text section address test`` () =
    Assert.AreEqual<uint64> (0x154UL, getTextSectionAddr file)

  [<TestMethod>]
  member __.``[Wasm] symbols length test`` () =
    Assert.AreEqual<int> (9, file.GetSymbols () |> Seq.length)

  [<TestMethod>]
  member __.``[Wasm] sections length test`` () =
    Assert.AreEqual<int> (12, file.GetSections () |> Seq.length)

  [<TestMethod>]
  member __.``[Wasm] linkageTableEntries length test`` () =
    Assert.AreEqual<int> (4, file.GetLinkageTableEntries () |> Seq.length)

  [<TestMethod>]
  member __.``[Wasm] function symbol test (1)`` () =
    assertFuncSymbolExistence file 0x0000007AUL "putc_js"

  [<TestMethod>]
  member __.``[Wasm] function symbol test (2)`` () =
    assertFuncSymbolExistence file 0x00000116UL "writev_c"
