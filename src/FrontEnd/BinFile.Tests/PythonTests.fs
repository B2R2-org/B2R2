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
type PythonTests() =
  static let bytes =
    ZIPReader.readBytes PythonBinary "python_basic.zip" "python_basic.pyc"

  static let file = PythonBinFile("", bytes, None)

  [<TestMethod>]
  member _.``[Python] format test``() =
    Assert.AreEqual(PythonBinary, (file :> IBinFile).Format)

  [<TestMethod>]
  member _.``[Python] magic test``() =
    Assert.AreEqual<uint32>(0x0A0D0DCBu, file.Magic)

  [<TestMethod>]
  member _.``[Python] ISA test``() =
    Assert.AreEqual(Architecture.Python, (file :> IBinFile).ISA.Arch)

  [<TestMethod>]
  member _.``[Python] kind test``() =
    Assert.AreEqual<BinFileKind>(Unknown, (file :> IBinFile).Kind)

  [<TestMethod>]
  member _.``[Python] entry point and base address test``() =
    Assert.AreEqual(Some 0UL, (file :> IBinFile).EntryPoint)
    Assert.AreEqual<uint64>(0UL, (file :> IBinFile).BaseAddress)

  [<TestMethod>]
  member _.``[Python] has no symbol table test``() =
    Assert.AreEqual<bool>(true, (file :> IBinFile).SymbolTable.IsNone)

  [<TestMethod>]
  member _.``[Python] consts are parsed test``() =
    Assert.AreEqual<bool>(true, file.Consts.Length > 0)

  [<TestMethod>]
  member _.``[Python] valid address test``() =
    let f = file :> IBinFile
    Assert.AreEqual<bool>(true, f.IsValidAddr 0UL)
    Assert.AreEqual<bool>(false, f.IsValidAddr 0x100000UL)

  [<TestMethod>]
  member _.``[Python] slice test``() =
    let f = file :> IBinFile
    let viaSlice = f.Slice(0UL, 4).ToArray()
    let viaRaw = f.RawBytes.Span.Slice(0, 4).ToArray()
    CollectionAssert.AreEqual(viaRaw, viaSlice)

  [<TestMethod>]
  member _.``[Python] format detector identifies Python test``() =
    let isa = ISA(Architecture.Intel, Endian.Little, WordSize.Bit64)
    let struct (fmt, _) = FormatDetector.identify bytes isa
    Assert.AreEqual(PythonBinary, fmt)
