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
  member _.``[Wasm] EntryPoint test`` () =
    Assert.AreEqual (Some 0x15AUL, file.EntryPoint)

  [<TestMethod>]
  member _.``[Wasm] file type test`` () =
    Assert.AreEqual (FileType.ExecutableFile, file.Type)

  [<TestMethod>]
  member _.``[Wasm] IsStripped test`` () =
    Assert.IsFalse (file.IsStripped)

  [<TestMethod>]
  member _.``[Wasm] text section address test`` () =
    Assert.AreEqual<uint64> (0x154UL, getTextSectionAddr file)

  [<TestMethod>]
  member _.``[Wasm] sections length test`` () =
    Assert.AreEqual<int> (12, (file :?> WasmBinFile).Sections.Length)

  [<TestMethod>]
  member _.``[Wasm] linkageTableEntries length test`` () =
    Assert.AreEqual<int> (4, file.GetLinkageTableEntries () |> Seq.length)
