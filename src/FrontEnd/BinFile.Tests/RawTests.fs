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
type RawTests() =
  static let isa = ISA(Architecture.Intel, Endian.Little, WordSize.Bit64)

  static let bytes = [| for i in 0 .. 15 -> byte i |]

  /// A raw blob loaded at base 0.
  static let rawFile = RawBinFile("raw", bytes, isa, None) :> IBinFile

  /// The same blob loaded at a non-zero base address.
  static let basedFile =
    RawBinFile("raw", bytes, isa, Some 0x4000UL) :> IBinFile

  [<TestMethod>]
  member _.``[Raw] format test``() =
    Assert.AreEqual(RawBinary, rawFile.Format)

  [<TestMethod>]
  member _.``[Raw] kind test``() =
    Assert.AreEqual<BinFileKind>(Unknown, rawFile.Kind)

  [<TestMethod>]
  member _.``[Raw] ISA test``() =
    Assert.AreEqual(Architecture.Intel, rawFile.ISA.Arch)
    Assert.AreEqual(WordSize.Bit64, rawFile.ISA.WordSize)

  [<TestMethod>]
  member _.``[Raw] entry point and base address test``() =
    Assert.AreEqual(Some 0UL, rawFile.EntryPoint)
    Assert.AreEqual<uint64>(0UL, rawFile.BaseAddress)

  [<TestMethod>]
  member _.``[Raw] property defaults test``() =
    Assert.AreEqual<bool>(false, rawFile.IsNXEnabled)
    Assert.AreEqual<bool>(false, rawFile.IsPIE)
    Assert.AreEqual<bool>(false, rawFile.IsBaseRelative)

  [<TestMethod>]
  member _.``[Raw] capability tables are absent test``() =
    Assert.AreEqual<bool>(true, rawFile.SymbolTable.IsNone)
    Assert.AreEqual<bool>(true, rawFile.Relocations.IsNone)
    Assert.AreEqual<bool>(true, rawFile.ExceptionTable.IsNone)
    Assert.AreEqual<bool>(true, rawFile.ImportTable.IsNone)
    Assert.AreEqual<bool>(true, rawFile.Structure.IsNone)
    Assert.AreEqual<bool>(true, rawFile.NameResolver.IsNone)

  [<TestMethod>]
  member _.``[Raw] memory layout is a single rwx segment test``() =
    let segs = rawFile.MemoryLayout.Value.Segments
    Assert.AreEqual<int>(1, segs.Length)
    Assert.AreEqual<uint64>(uint64 bytes.Length, segs[0].Size)
    let rwx =
      Permission.Readable ||| Permission.Writable ||| Permission.Executable
    Assert.AreEqual<Permission>(rwx, segs[0].Permission)

  [<TestMethod>]
  member _.``[Raw] valid address test``() =
    Assert.AreEqual<bool>(true, rawFile.IsValidAddr 0UL)
    Assert.AreEqual<bool>(true, rawFile.IsValidAddr 0xFUL)
    Assert.AreEqual<bool>(false, rawFile.IsValidAddr 0x10UL)

  [<TestMethod>]
  member _.``[Raw] executable address test``() =
    Assert.AreEqual<bool>(true, rawFile.IsExecutableAddr 0UL)

  [<TestMethod>]
  member _.``[Raw] slice test``() =
    let s = rawFile.Slice(0x4UL, 4).ToArray()
    CollectionAssert.AreEqual([| 4uy; 5uy; 6uy; 7uy |], s)

  [<TestMethod>]
  member _.``[Raw] bounded pointer test``() =
    let p = rawFile.GetBoundedPointer 0x4UL
    Assert.AreEqual<bool>(false, p.IsNull)
    Assert.AreEqual<bool>(true, p.CanReadFileBytes)
    Assert.AreEqual<bool>(true, (rawFile.GetBoundedPointer 0x100UL).IsNull)

  [<TestMethod>]
  member _.``[Raw] base address override test``() =
    Assert.AreEqual(Some 0x4000UL, basedFile.EntryPoint)
    Assert.AreEqual<uint64>(0x4000UL, basedFile.BaseAddress)
    Assert.AreEqual<bool>(true, basedFile.IsValidAddr 0x4000UL)
    Assert.AreEqual<bool>(false, basedFile.IsValidAddr 0UL)

  [<TestMethod>]
  member _.``[Raw] based slice maps to offset test``() =
    let s = basedFile.Slice(0x4004UL, 4).ToArray()
    CollectionAssert.AreEqual([| 4uy; 5uy; 6uy; 7uy |], s)
