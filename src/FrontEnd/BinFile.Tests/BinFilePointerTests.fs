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

[<TestClass>]
type BinFilePointerTests() =
  /// A pointer to a 16-byte region mapped to both VM and file.
  static let fileBacked = BinFilePointer.CreateFileBacked(0UL, 15UL, 0, 15)

  /// A pointer to a 0x1000-byte region mapped to VM only, as in a .bss section.
  static let vmOnly = BinFilePointer.CreateVirtual(0x1000UL, 0x1fffUL)

  [<TestMethod>]
  member _.``[BinFilePointer] file-backed pointer read test``() =
    Assert.AreEqual<bool>(false, fileBacked.IsNull)
    Assert.AreEqual<bool>(false, fileBacked.IsVirtual)
    Assert.AreEqual<bool>(true, fileBacked.CanReadFileBytes)
    Assert.AreEqual<int>(16, fileBacked.ReadableAmount)
    Assert.AreEqual<bool>(true, fileBacked.CanRead 1)
    Assert.AreEqual<bool>(true, fileBacked.CanRead 16)
    Assert.AreEqual<bool>(false, fileBacked.CanRead 17)

  (* A VM-only region has no file bytes to bound the read with, so CanRead must
     answer from the address range alone. *)
  [<TestMethod>]
  member _.``[BinFilePointer] VM-only pointer read test``() =
    Assert.AreEqual<bool>(false, vmOnly.IsNull)
    Assert.AreEqual<bool>(true, vmOnly.IsVirtual)
    Assert.AreEqual<bool>(false, vmOnly.CanReadFileBytes)
    Assert.AreEqual<bool>(true, vmOnly.CanRead 1)
    Assert.AreEqual<bool>(true, vmOnly.CanRead 0x1000)
    Assert.AreEqual<bool>(false, vmOnly.CanRead 0x1001)

  (* A null pointer carries no valid file offset, so it must refuse every read.
     Its degenerate address range [0, 0] would otherwise let a single-byte read
     through and reach a negative offset. *)
  [<TestMethod>]
  member _.``[BinFilePointer] null pointer read test``() =
    let nullPtr = BinFilePointer.Null
    Assert.AreEqual<bool>(true, nullPtr.IsNull)
    Assert.AreEqual<bool>(false, nullPtr.CanReadFileBytes)
    Assert.AreEqual<bool>(false, nullPtr.CanRead 1)
    Assert.AreEqual<bool>(false, nullPtr.CanRead 4)

  [<TestMethod>]
  member _.``[BinFilePointer] non-positive size read test``() =
    Assert.AreEqual<bool>(false, fileBacked.CanRead 0)
    Assert.AreEqual<bool>(false, fileBacked.CanRead -1)
    Assert.AreEqual<bool>(false, vmOnly.CanRead 0)

  [<TestMethod>]
  member _.``[BinFilePointer] pointer advanced within the region test``() =
    let ptr = fileBacked.Advance 4
    Assert.AreEqual<uint64>(4UL, ptr.Addr)
    Assert.AreEqual<int>(4, ptr.Offset)
    Assert.AreEqual<int>(12, ptr.ReadableAmount)
    Assert.AreEqual<bool>(true, ptr.CanRead 12)
    Assert.AreEqual<bool>(false, ptr.CanRead 13)

  (* Advancing out of the file-backed region clamps the offset one past the max
     offset, which makes the pointer report itself as virtual. Its address has
     left the range, though, so it must still refuse every read. *)
  [<TestMethod>]
  member _.``[BinFilePointer] pointer advanced past the end test``() =
    let ptr = fileBacked.Advance 16
    Assert.AreEqual<bool>(true, ptr.IsVirtual)
    Assert.AreEqual<bool>(false, ptr.CanReadFileBytes)
    Assert.AreEqual<bool>(false, ptr.CanRead 1)
