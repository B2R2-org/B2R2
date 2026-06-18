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
type WasmTests() =
  static let parseFile fileName =
    let zipFile = fileName + ".zip"
    let fileNameInZip = fileName + ".wasm"
    let bytes = ZIPReader.readBytes WasmBinary zipFile fileNameInZip
    WasmBinFile("", bytes) :> IBinFile

  static let file = parseFile "wasm_basic"

  [<TestMethod>]
  member _.``[Wasm] format test``() =
    Assert.AreEqual(WasmBinary, file.Format)

  [<TestMethod>]
  member _.``[Wasm] ISA test``() =
    Assert.AreEqual(Architecture.WASM, file.ISA.Arch)

  [<TestMethod>]
  member _.``[Wasm] kind test``() =
    Assert.AreEqual<BinFileKind>(Unknown, file.Kind)

  [<TestMethod>]
  member _.``[Wasm] base address test``() =
    Assert.AreEqual<uint64>(0UL, file.BaseAddress)

  [<TestMethod>]
  member _.``[Wasm] has no symbol table test``() =
    match file.SymbolTable with
    | None -> ()
    | Some _ -> Assert.Fail "Wasm should not provide a symbol table."

  [<TestMethod>]
  member _.``[Wasm] property defaults test``() =
    Assert.AreEqual<bool>(true, file.IsNXEnabled)
    Assert.AreEqual<bool>(false, file.IsPIE)
    Assert.AreEqual<bool>(false, file.IsBaseRelative)

  [<TestMethod>]
  member _.``[Wasm] sections length test``() =
    Assert.AreEqual<int>(8, (file :?> WasmBinFile).Sections.Length)

  [<TestMethod>]
  member _.``[Wasm] text section address test``() =
    Assert.AreEqual<uint64>(0x47UL, getTextSectionAddr file)

  [<TestMethod>]
  member _.``[Wasm] linkageTableEntries length test``() =
    Assert.AreEqual<int>(1, getLinkageTableEntries file |> Seq.length)

  [<TestMethod>]
  member _.``[Wasm] name section resolves the entry point name``() =
    let resolver = Option.get file.NameResolver
    Assert.AreEqual<Result<string, _>>(
      Ok "__wasm_call_ctors", resolver.TryResolveName file.EntryPoint.Value)

  [<TestMethod>]
  member _.``[Wasm] name section resolves an imported function name``() =
    let hasPutcJs =
      getLinkageTableEntries file |> Seq.exists (fun i -> i.Name = "putc_js")
    Assert.AreEqual<bool>(true, hasPutcJs)

  [<TestMethod>]
  member _.``[Wasm] name section resolves a local function name``() =
    let resolver = Option.get file.NameResolver
    let hasMain =
      file.Structure.Value.FunctionAddresses
      |> Array.exists (fun a -> resolver.TryResolveName a = Ok "main")
    Assert.AreEqual<bool>(true, hasMain)

  [<TestMethod>]
  member _.``[Wasm] valid address test``() =
    Assert.AreEqual<bool>(true, file.IsValidAddr 0x49UL)
    Assert.AreEqual<bool>(false, file.IsValidAddr 0x100000UL)

  [<TestMethod>]
  member _.``[Wasm] slice maps offset to content test``() =
    let viaSlice = file.Slice(0x49UL, 4).ToArray()
    let viaRaw = file.RawBytes.Span.Slice(0x49, 4).ToArray()
    CollectionAssert.AreEqual(viaRaw, viaSlice)

  [<TestMethod>]
  member _.``[Wasm] format detector identifies Wasm test``() =
    let bytes =
      ZIPReader.readBytes WasmBinary "wasm_basic.zip" "wasm_basic.wasm"
    let isa = ISA(Architecture.Intel, Endian.Little, WordSize.Bit64)
    let struct (fmt, _) = FormatDetector.identify bytes isa
    Assert.AreEqual(WasmBinary, fmt)
